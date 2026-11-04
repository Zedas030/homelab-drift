"""Generate the documentation: static HTML (www/) and Markdown (repo/docs/, repo/CHANGELOG.md) from the current state.

Sources: current state per host/collector (state/current), findings, changelog, your annotations.
Annotations are merged in but never modified.
"""
from __future__ import annotations

import datetime as dt
import re
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from . import __version__
from .annotations import Annotations
from .collectors import Collector
from .config import Config
from .store import ACKED, OPEN, Changelog, State
from .util import human_duration, now, parse_iso, read_json, write_atomic

COLLECTOR_ORDER = ["system", "docker", "ports", "nginx", "cron", "systemd", "storage", "tailscale", "fritzbox"]
SECTION_TITLES = {"docker": "Docker containers", "ports": "Listening ports", "nginx": "nginx sites", "cron": "Cron jobs",
                  "systemd": "systemd services and timers", "storage": "Mounts and storage", "tailscale": "Tailscale",
                  "fritzbox": "Devices on the network (FRITZ!Box)"}


def slug(*parts: str) -> str:
    s = "-".join(parts)
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", s).strip("_")


def fmt_bytes(n: Any) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "–"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def fmt_ts(s: str | None) -> str:
    if not s:
        return "–"
    try:
        return parse_iso(s).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return s


WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def day(s: str) -> str:
    try:
        d = dt.date.fromisoformat(s[:10])
    except ValueError:
        return s
    return f"{WEEKDAYS[d.weekday()]}, {d:%Y-%m-%d}"


def since(s: str | None) -> str:
    if not s:
        return "–"
    return human_duration((now() - parse_iso(s)).total_seconds())


class Renderer:
    def __init__(self, cfg: Config, st: State, changelog: Changelog, notes: Annotations, reg: dict[str, Collector],
                 host_meta: dict[str, dict], git_log: list[dict] | None = None):
        self.cfg, self.st, self.cl, self.notes, self.reg = cfg, st, changelog, notes, reg
        self.host_meta = host_meta
        self.git_log = git_log or []
        self.env = Environment(loader=PackageLoader("homelab_drift", "templates"),
                               autoescape=select_autoescape(["html"]), trim_blocks=True, lstrip_blocks=True)
        self.env.filters.update(bytes=fmt_bytes, ts=fmt_ts, since=since, slug=slug, day=day,
                                joinl=lambda v, sep=", ": sep.join(map(str, v)) if isinstance(v, list) else (v or ""))

    # ------------------------------------------------------------------ Daten
    def current(self, host: str, collector: str) -> list[dict]:
        return read_json(self.cfg.data_dir / "current" / host / f"{collector}.json", {}).get("items", [])

    def _enrich(self, host: str, collector: str, items: list[dict]) -> list[dict]:
        open_by_item: dict[str, list[dict]] = defaultdict(list)
        for f in self.st.findings:
            if f["host"] == host and f["collector"] == collector and f["status"] in (OPEN, ACKED):
                open_by_item[f["item_id"]].append(f)
        out = []
        for it in items:
            n = self.notes.get(host, collector, it["id"])
            out.append({**it, "_note": n.note, "_known": n.acknowledged(), "_documented": n.documented,
                        "_findings": open_by_item.get(it["id"], [])})
        return out

    def model(self) -> dict:
        hosts = []
        all_ports = []
        services = []
        for h in self.cfg.hosts:
            meta = self.host_meta.get(h.name, {})
            cols: dict[str, Any] = {}
            for c in COLLECTOR_ORDER:
                if c not in h.collectors:
                    continue
                cm = meta.get("collectors", {}).get(c, {})
                cols[c] = {"status": cm.get("status", "unbekannt"), "error": cm.get("error", ""),
                           "items": self._enrich(h.name, c, self.current(h.name, c))}
            system = (cols.get("system", {}).get("items") or [{}])[0]
            docker = cols.get("docker", {}).get("items", [])
            nginx = cols.get("nginx", {}).get("items", [])
            # port -> service: annotation > container (docker-proxy) > nginx site > process
            for p in cols.get("ports", {}).get("items", []):
                svc, link = "", ""
                if p.get("port"):
                    # running containers first: a stopped one with the same port binding is not listening
                    for d in sorted(docker, key=lambda x: not x.get("running")):
                        if any(re.search(rf":{p['port']}->", x) for x in d.get("ports", [])):
                            svc, link = f"Container {d['id']}", f"service-{slug(h.name, 'docker', d['id'])}.html"
                            break
                    if not svc and "nginx" in p.get("processes", []):
                        for n in nginx:
                            if p["port"] in n.get("ports", []):
                                svc, link = f"nginx site {n['id'].split(':')[0]}", f"service-{slug(h.name, 'nginx', n['id'])}.html"
                p["_service"], p["_service_link"] = svc or ", ".join(p.get("processes", [])), link
                all_ports.append({"host": h.name, **p})
            for c in ("docker", "systemd", "nginx"):
                for it in cols.get(c, {}).get("items", []):
                    services.append({"host": h.name, "collector": c, "item": it, "volatile": self.reg[c].volatile,
                                     "file": f"service-{slug(h.name, c, it['id'])}.html"})
            hosts.append({"name": h.name, "type": h.type, "address": h.address, "description": h.description,
                          "note": self.notes.host_note(h.name), "reachable": meta.get("reachable"),
                          "error": meta.get("error", ""), "scanned_at": meta.get("scanned_at"),
                          "last_ok": meta.get("last_ok"), "system": system, "cols": cols,
                          "n_public": sum(1 for p in cols.get("ports", {}).get("items", []) if p.get("exposure") in ("all", "LAN")),
                          "n_undoc": sum(1 for c in cols.values() for i in c["items"] if not i["_documented"])})
        findings_open = sorted(self.st.open_findings(), key=lambda f: (f["severity"] != "instant", f["created"]))
        findings_acked = [f for f in self.st.findings if f["status"] == ACKED]
        return {
            "cfg": self.cfg, "version": __version__, "generated": now().isoformat(timespec="seconds"),
            "meta": self.st.meta, "hosts": hosts, "ports": sorted(all_ports, key=lambda p: (p["port"] is None, p["port"] or 0, p["host"])),
            "services": services, "findings_open": findings_open, "findings_acked": findings_acked,
            "pending": len(self.st.pending), "outbox": len(self.st.outbox), "warnings": self.notes.warnings,
            "changelog": self.cl.read(), "git_log": self.git_log, "titles": SECTION_TITLES,
            "has_acceptance": (self.cfg.www_dir / "acceptance.html").exists(),
        }

    def item_history(self, host: str, collector: str, iid: str, changelog: list[dict]) -> list[dict]:
        return [e for e in changelog if e.get("host") == host and e.get("collector") == collector and e.get("item") == iid]

    # ------------------------------------------------------------------ Ausgabe
    def write(self) -> list[Path]:
        m = self.model()
        www = self.cfg.www_dir
        www.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []

        def out(path: Path, tpl: str, **kw: Any) -> None:
            write_atomic(path, self.env.get_template(tpl).render(**m, **kw))
            written.append(path)

        out(www / "index.html", "index.html", page="index")
        out(www / "ports.html", "ports.html", page="ports")
        out(www / "changelog.html", "changelog.html", page="changelog")
        for h in m["hosts"]:
            out(www / f"host-{slug(h['name'])}.html", "host.html", page="host", host=h)
        keep = {"index.html", "ports.html", "changelog.html", "metrics", "acceptance.html", "style.css"}
        keep |= {f"host-{slug(h['name'])}.html" for h in m["hosts"]}
        for s in m["services"]:
            hist = self.item_history(s["host"], s["collector"], s["item"]["id"], m["changelog"])
            out(www / s["file"], "service.html", page="service", s=s, history=hist)
            keep.add(s["file"])
        # remove pages of services that are gone (otherwise the docs would lie)
        for p in www.glob("*.html"):
            if p.name not in keep:
                p.unlink()
        # Markdown into the repo
        repo = self.cfg.repo_dir
        docs = repo / "docs"
        if docs.exists():
            shutil.rmtree(docs)
        docs.mkdir(parents=True)
        write_atomic(docs / "index.md", self.env.get_template("index.md").render(**m))
        write_atomic(docs / "ports.md", self.env.get_template("ports.md").render(**m))
        for h in m["hosts"]:
            write_atomic(docs / f"{slug(h['name'])}.md", self.env.get_template("host.md").render(**m, host=h))
        (docs / "services").mkdir()
        for s in m["services"]:
            write_atomic(docs / "services" / s["file"].replace(".html", ".md"),
                         self.env.get_template("service.md").render(**m, s=s))
        write_atomic(repo / "CHANGELOG.md", self.env.get_template("changelog.md").render(**m))
        return written
