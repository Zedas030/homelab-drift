"""Drift detection: comparison with the baseline, noise filter (N scans in a row), classification, acknowledgement, changelog.

Per item:
1. If it differs from the baseline, the difference is counted as an "observation" (pending).
2. If the difference disappears before N scans or changes again, counting starts over (flapping, short restart).
3. After N scans it is confirmed: the baseline is updated, a changelog entry is written, a finding gets an ID (D-0001 …).
4. If the item is documented/acknowledged (annotation with ``known: true``) there is no alert.
   Otherwise: instant alert for undocumented + security-relevant changes, everything else goes into the daily digest.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

from .annotations import Annotations
from .collectors import Collector
from .collectors.ports import PortsCollector
from .config import Config
from .store import ACKED, CLOSED, OPEN, Changelog, State
from .util import human_duration, iso, now, parse_iso, short_hash

INSTANT, DIGEST = "instant", "digest"
ADDED, REMOVED, CHANGED, HEALTH = "added", "removed", "changed", "health"
ACK_HINT = "\nIs this expected? Acknowledge with: homelab-drift ack"


@dataclass
class CollectResult:
    status: str  # ok | error | unavailable
    items: list[dict] = field(default_factory=list)
    error: str = ""


@dataclass
class HostResult:
    host: str
    reachable: bool
    error: str = ""
    collectors: dict[str, CollectResult] = field(default_factory=dict)


@dataclass
class Summary:
    confirmed: list[dict] = field(default_factory=list)   # new findings of this scan
    changes: int = 0
    pending: int = 0
    health_problems: list[str] = field(default_factory=list)
    first_inventory: list[str] = field(default_factory=list)
    paused: str | None = None                             # maintenance unit that caused a skipped scan


def _public_ports(item: dict | None) -> set[str]:
    return {p for p in (item or {}).get("ports", []) if not p.startswith(("127.", "[::1]", "::1"))}


class Engine:
    def __init__(self, cfg: Config, state: State, changelog: Changelog, notes: Annotations, registry: dict[str, Collector]):
        self.cfg, self.state, self.changelog, self.notes, self.reg = cfg, state, changelog, notes, registry

    # ------------------------------------------------------------------ entry point
    def process(self, results: list[HostResult]) -> Summary:
        s = Summary()
        self._check_scan_gap()
        self._forget_removed_hosts()
        for hr in results:
            if not hr.reachable:
                self._host_unreachable(hr, s)
                continue
            self._host_reachable(hr.host)
            for cname, cr in hr.collectors.items():
                self._process_collector(hr.host, cname, cr, s)
        self._apply_yaml_acks()
        s.pending = len(self.state.pending)
        t = iso()
        self.state.meta["last_scan"] = t
        if not s.health_problems:
            self.state.meta["last_success"] = t
        self.state.meta["scans"] = int(self.state.meta.get("scans", 0)) + 1
        return s

    def _forget_removed_hosts(self) -> None:
        """Host removed from config.yaml -> drop its baseline and observations, close its open findings."""
        known = {h.name for h in self.cfg.hosts} | {"-"}
        gone = (set(self.state.baseline) | {f["host"] for f in self.state.findings if f["status"] != CLOSED}) - known
        for host in sorted(gone):
            self.state.baseline.pop(host, None)
            for k in [k for k in self.state.pending if k.startswith(f"{host}|")]:
                del self.state.pending[k]
            for k in [k for k in self.state.health if k.endswith(f":{host}") or f":{host}/" in k]:
                del self.state.health[k]
            for f in self.state.findings:
                if f["host"] == host and f["status"] != CLOSED:
                    self.state.close(f, "host removed from the configuration")
            self.changelog.append({"host": host, "collector": "-", "item": "*", "kind": "host",
                                   "summary": f"Host {host} removed from the configuration - no longer monitored"})

    # ------------------------------------------------------------------ health
    def _check_scan_gap(self) -> None:
        last = self.state.meta.get("last_scan")
        if not last:
            return
        gap = (now() - parse_iso(last)).total_seconds()
        if gap > 3 * self.cfg.scan_interval_minutes * 60:
            msg = (f"Homelab-Drift did not scan for {human_duration(gap)} (last scan {last[:16].replace('T', ' ')}). "
                   "It is running again.")
            self.changelog.append({"host": "-", "collector": "self", "item": "scan", "kind": HEALTH, "summary": msg})
            self._notify(INSTANT, "Homelab-Drift is running again", msg, [])

    def _health(self, key: str, host: str, collector: str, problem: str | None, title: str, s: Summary,
                threshold: int) -> None:
        """Counts consecutive problems; from `threshold` on an instant finding, all-clear once it recovers."""
        h = self.state.health.setdefault(key, {"count": 0})
        f = self.state.health_finding(key)
        if problem is None:
            if h.get("count"):
                h.update(count=0, since=None)
            if f:
                self.state.close(f, "recovered")
                self.changelog.append({"host": host, "collector": collector, "item": key, "kind": HEALTH,
                                       "summary": f"Resolved: {title} - back to normal", "finding": f["id"]})
                if f.get("notified"):
                    self._notify(INSTANT, f"Resolved: {host}", f"{title}: back to normal.", [f["id"]])
            return
        h["count"] = int(h.get("count", 0)) + 1
        if not h.get("since"):
            h["since"] = iso()
        h["last_error"] = problem
        s.health_problems.append(f"{host}/{collector}: {problem}")
        if h["count"] >= threshold and not f:
            f = self._new_finding(host, collector, key, HEALTH, INSTANT, title, problem, None, None,
                                  first_seen=h["since"], health_key=key)
            s.confirmed.append(f)
            self.changelog.append({"host": host, "collector": collector, "item": key, "kind": HEALTH,
                                   "summary": f"{title}: {problem}", "finding": f["id"]})
            self._alert(f)

    def _host_unreachable(self, hr: HostResult, s: Summary) -> None:
        self._health(f"unreachable:{hr.host}", hr.host, "ssh", hr.error or "no connection",
                     f"Host {hr.host} unreachable", s, self.cfg.unreachable_after_scans)

    def _host_reachable(self, host: str) -> None:
        self._health(f"unreachable:{host}", host, "ssh", None, f"Host {host} unreachable", Summary(), 1)

    # ------------------------------------------------------------------ per collector
    def _process_collector(self, host: str, cname: str, cr: CollectResult, s: Summary) -> None:
        col = self.reg[cname]
        base = self.state.baseline.setdefault(host, {})
        key = f"collector:{host}/{cname}"
        title = f"Collector {cname} on {host}"
        thr = self.cfg.unreachable_after_scans
        if cr.status == "unavailable":
            if base.get(cname):
                self._health(key, host, cname, f"tool no longer available ({cr.error})", title + " returns nothing", s, thr)
            return
        if cr.status == "error":
            self._health(key, host, cname, cr.error or "error", title + " failed", s, thr)
            return
        if cname not in base:
            base[cname] = {i["id"]: i for i in cr.items}
            s.first_inventory.append(f"{host}/{cname}")
            self.changelog.append({"host": host, "collector": cname, "item": "*", "kind": "inventory",
                                   "summary": f"Initial inventory {col.label}: {len(cr.items)} items"})
            self._health(key, host, cname, None, title, s, thr)
            return
        empty_key = f"empty:{host}/{cname}"
        if base[cname] and not cr.items:
            ef = self.state.health_finding(empty_key)
            if not (ef and ef["status"] == ACKED):  # acknowledged = "empty is correct now"
                self._health(empty_key, host, cname, f"0 items instead of {len(base[cname])}",
                             title + " suddenly returns nothing", s, thr)
                return
        else:
            self._health(empty_key, host, cname, None, title + " suddenly returns nothing", s, thr)
        self._health(key, host, cname, None, title + " failed", s, thr)
        self._diff(host, col, base[cname], {i["id"]: i for i in cr.items}, s)

    def _diff(self, host: str, col: Collector, base: dict[str, dict], cur: dict[str, dict], s: Summary) -> None:
        prefix = f"{host}|{col.name}|"
        seen = set()
        for iid in sorted(set(base) | set(cur)):
            b, c = base.get(iid), cur.get(iid)
            if b is not None and c is not None and any(k not in b for k in col.compare):
                base[iid] = c  # baseline from an older version without this compare field: adopt silently
                continue
            bc = col.comparable(b) if b else None
            cc = col.comparable(c) if c else None
            if bc == cc:
                # keep info fields (usage, PIDs …) current without counting them as drift
                if c is not None:
                    base[iid] = c
                continue
            pkey = prefix + iid
            seen.add(pkey)
            sig = short_hash(cc)
            p = self.state.pending.get(pkey)
            if not p or p["sig"] != sig:
                p = {"sig": sig, "count": 0, "first_seen": iso()}
                self.state.pending[pkey] = p
            p["count"] += 1
            p["last_seen"] = iso()
            if p["count"] >= self.cfg.confirm_after_scans:
                del self.state.pending[pkey]
                self._confirm(host, col, iid, b, c, p["first_seen"], s)
                if c is None:
                    base.pop(iid, None)
                else:
                    base[iid] = c
        # drop observations whose difference has disappeared (flapping)
        for pkey in [k for k in self.state.pending if k.startswith(prefix) and k not in seen]:
            del self.state.pending[pkey]

    # ------------------------------------------------------------------ confirmation
    def _confirm(self, host: str, col: Collector, iid: str, before: dict | None, after: dict | None, first_seen: str,
                 s: Summary) -> None:
        s.changes += 1
        kind = ADDED if before is None else REMOVED if after is None else CHANGED
        item = after or before or {"id": iid}
        title, details = self._describe(col, kind, before, after)
        prev = self.state.for_item(host, col.name, iid)
        open_prev = [f for f in prev if f["status"] == OPEN]
        # Back to the original state of a still OPEN finding? Then both cancel out.
        # (An acknowledged finding accepted the new state - going back is a change again.)
        if open_prev:
            origin = open_prev[0].get("before")
            if (col.comparable(origin) if origin else None) == (col.comparable(after) if after else None):
                for f in open_prev:
                    self.state.close(f, "reverted: original state restored")
                self.changelog.append({"host": host, "collector": col.name, "item": iid, "kind": "reverted",
                                       "summary": f"{col.describe(item)}: back to the previous state ({title})",
                                       "finding": open_prev[-1]["id"]})
                return
        note = self.notes.get(host, col.name, iid)
        severity = self._severity(col, kind, before, after, documented=note.documented)
        f = self._new_finding(host, col.name, iid, kind, severity, title, details, before, after, first_seen=first_seen)
        f["documented"] = note.documented
        if open_prev:
            f["before"] = open_prev[0].get("before")  # open chain: origin of the first finding (also "did not exist")
        for old in prev:
            self.state.close(old, f"superseded by {f['id']}")
        if note.acknowledged():
            self.state.ack(f, via="annotations.yaml", reason=note.reason or "known: true",
                           until=str(note.until) if note.until else None)
        s.confirmed.append(f)
        self.changelog.append({"host": host, "collector": col.name, "item": iid, "kind": kind, "severity": severity,
                               "summary": title, "details": details, "finding": f["id"], "status": f["status"]})
        if f["status"] == OPEN and severity == INSTANT:
            self._alert(f)

    def _severity(self, col: Collector, kind: str, before: dict | None, after: dict | None, documented: bool) -> str:
        if documented:
            return DIGEST
        a, b = after or {}, before or {}
        if col.name == "ports":
            if kind == ADDED and PortsCollector.is_public(a):
                return INSTANT
            if kind == CHANGED and PortsCollector.is_public(a) and not PortsCollector.is_public(b):
                return INSTANT
        if col.name == "cron" and kind == ADDED and a.get("user") == "root":
            return INSTANT
        if col.name == "systemd" and kind == ADDED and a.get("kind") == "timer" and a.get("user") == "root":
            return INSTANT
        if col.name == "docker":
            if kind == ADDED and (a.get("privileged") or a.get("network_mode") == "host" or _public_ports(a)):
                return INSTANT
            if kind == CHANGED and ((a.get("privileged") and not b.get("privileged"))
                                    or (_public_ports(a) - _public_ports(b))
                                    or (a.get("network_mode") == "host" and b.get("network_mode") != "host")):
                return INSTANT
        return DIGEST

    # ------------------------------------------------------------------ texts
    def _describe(self, col: Collector, kind: str, b: dict | None, a: dict | None) -> tuple[str, str]:
        item = a or b or {}
        name = col.describe(item)
        if kind == ADDED:
            extra = ""
            if col.name == "ports":
                extra = f" (exposed: {a.get('exposure')}, process {', '.join(a.get('processes', []))})"
            elif col.name == "docker":
                extra = f" ({a.get('image')}" + (f", ports {', '.join(a['ports'])}" if a.get("ports") else "") + ")"
            elif col.name == "cron":
                extra = f" running as {a.get('user')}"
            return f"{name} is new{extra}", self._fields(col, None, a)
        if kind == REMOVED:
            return f"{name} is gone", self._fields(col, b, None)
        changed = [k for k in col.compare if (b or {}).get(k) != (a or {}).get(k)]
        if col.name == "docker" and "image_id" in changed:
            vb, va = b.get("version") or b.get("image_id"), a.get("version") or a.get("image_id")
            return f"Image of {item['id']} updated ({vb} → {va})", self._fields(col, b, a)
        if col.name == "docker" and changed == ["running"]:
            return f"{name} {'is running again' if a.get('running') else 'stopped'}", self._fields(col, b, a)
        if col.name == "system" and "boot_time" in changed and len(changed) == 1:
            return f"Host rebooted (boot {a.get('boot_time', '')[:16].replace('T', ' ')})", ""
        if col.name == "system" and "kernel" in changed:
            return f"Kernel updated ({b.get('kernel')} → {a.get('kernel')})", self._fields(col, b, a)
        if col.name == "storage" and "level" in changed:
            return f"{name}: usage {a.get('use_percent')} % ({a.get('level')})", self._fields(col, b, a)
        if col.name == "systemd" and "run_state" in changed and a.get("run_state") == "failed":
            return f"{name} failed", self._fields(col, b, a)
        return f"{name} changed: {', '.join(changed)}", self._fields(col, b, a)

    @staticmethod
    def _fmt(v: Any) -> str:
        if isinstance(v, list):
            return ", ".join(map(str, v)) or "–"
        if v is None or v == "":
            return "–"
        return str(v)

    def _fields(self, col: Collector, b: dict | None, a: dict | None) -> str:
        rows = []
        for k in col.compare:
            vb = self._fmt((b or {}).get(k)) if b else None
            va = self._fmt((a or {}).get(k)) if a else None
            if b and a:
                if vb != va:
                    rows.append(f"{k}: {vb} → {va}")
            else:
                rows.append(f"{k}: {va if a else vb}")
        return "; ".join(rows)

    # ------------------------------------------------------------------ findings & alerts
    def _new_finding(self, host: str, collector: str, item_id: str, kind: str, severity: str, title: str, details: str,
                     before: dict | None, after: dict | None, first_seen: str, health_key: str | None = None) -> dict:
        f = {"id": self.state.next_id(), "created": iso(), "first_seen": first_seen, "host": host, "collector": collector,
             "item_id": item_id, "kind": kind, "severity": severity, "title": title, "details": details,
             "before": before, "after": after, "status": OPEN, "notified": False, "digested": False,
             "documented": False}
        if health_key:
            f["health_key"] = health_key
        self.state.findings.append(f)
        return f

    def _alert(self, f: dict) -> None:
        if not self.cfg.notify_instant:
            return
        hint = "" if f["kind"] == HEALTH else f"{ACK_HINT} {f['id']} - or document it in annotations.yaml."
        # (several instant alerts of one host from one scan are merged into one push by notify._bundle)
        undoc = "" if f["kind"] == HEALTH or f.get("documented") else " - not documented anywhere"
        body = f"{f['title']}: {f['details']}" if f["kind"] == HEALTH and f.get("details") else f"{f['title']}{undoc}."
        title = "Homelab-Drift" if f["host"] == "-" else f"Homelab-Drift: {f['host']}"
        self._notify(INSTANT, title, f"{body}{hint}", [f["id"]])
        f["notified"] = True

    def _notify(self, kind: str, title: str, message: str, ids: list[str]) -> None:
        self.state.outbox.append({"kind": kind, "title": title, "message": message, "findings": ids,
                                  "created": iso(), "tries": 0})

    # ------------------------------------------------------------------ acknowledgements from the YAML
    def _apply_yaml_acks(self) -> None:
        today = dt.date.today()
        for f in self.state.findings:
            if f["kind"] == HEALTH:
                continue
            note = self.notes.get(f["host"], f["collector"], f["item_id"])
            if f["status"] == OPEN and note.acknowledged(today):
                self.state.ack(f, via="annotations.yaml", reason=note.reason or "known: true",
                               until=str(note.until) if note.until else None)
            elif f["status"] == ACKED and (f.get("ack") or {}).get("via") == "annotations.yaml" and not note.acknowledged(today):
                f["status"] = OPEN  # acknowledgement expired or removed from the YAML
                f.pop("ack", None)
            if f["status"] != CLOSED:
                f["documented"] = note.documented


def digest(cfg: Config, state: State) -> tuple[str, str] | None:
    """Daily digest: new open findings since the last digest plus a reminder about older open ones."""
    new = [f for f in state.findings if f["status"] == OPEN and not f.get("digested")]
    old = [f for f in state.findings if f["status"] == OPEN and f.get("digested")]
    state.meta["last_digest"] = iso()
    if not new and not old:
        if not cfg.notify_digest_empty:
            return None
        return "Homelab-Drift: daily digest", "No open findings. Everything matches the documentation."
    lines = []
    for f in sorted(new, key=lambda x: (x["host"], x["created"])):
        since = human_duration((now() - parse_iso(f["first_seen"])).total_seconds())
        lines.append(f"• [{f['id']}] {f['host']}: {f['title']} (for {since})")
        f["digested"] = True
    if old:
        oldest = min(old, key=lambda x: x["first_seen"])
        lines.append(f"Plus {len(old)} older open finding(s), the oldest for "
                     f"{human_duration((now() - parse_iso(oldest['first_seen'])).total_seconds())}: "
                     f"{', '.join(o['id'] for o in old[:8])}{' …' if len(old) > 8 else ''}")
    lines.append("Acknowledge: homelab-drift ack <ID> · Overview: " + cfg.base_url)
    head = f"{len(new)} new finding(s)" if new else "no new findings"
    return f"Homelab-Drift: daily digest - {head}", "\n".join(lines)
