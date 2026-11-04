"""One scan end to end: collect -> store -> compare -> alert -> docs -> git."""
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable

from . import annotations as ann
from . import metrics
from .collectors import Ctx, ParseError, registry
from .config import Config, Host
from .engine import INSTANT, CollectResult, Engine, HostResult, Summary, digest
from .gitrepo import GitRepo
from .notify import HAError, HomeAssistant, flush_outbox
from .render import Renderer
from .store import ACKED, OPEN, Changelog, State
from .transport import Runner, Unreachable, ssh_runner
from .util import file_lock, iso, log, read_json, write_atomic, write_json

REG = registry()


@dataclass
class Context:
    cfg: Config
    state: State
    changelog: Changelog
    notes: ann.Annotations
    host_meta: dict[str, dict]
    git: GitRepo | None


def open_context(cfg: Config) -> Context:
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    st = State.load(cfg.data_dir)
    notes = load_notes(cfg, st)
    git = GitRepo(cfg.repo_dir) if cfg.git_enabled else None
    return Context(cfg, st, Changelog(cfg.data_dir), notes, read_json(cfg.data_dir / "hosts.json", {}), git)


def load_notes(cfg: Config, st: State) -> ann.Annotations:
    """Load the annotations. If the YAML is broken, the last good version stays in effect and an alert is raised."""
    cache = cfg.data_dir / "annotations.last-good.json"
    try:
        notes = ann.load(cfg.annotations_file, [h.name for h in cfg.hosts], list(REG))
        write_json(cache, notes.data, mode=0o640)
        st.meta.pop("annotations_error", None)
        return notes
    except ann.AnnotationsError as e:
        log.error("%s - using the last good version", e)
        st.meta["annotations_error"] = str(e)
        return ann.Annotations(read_json(cache, {}), [f"{e} - the last valid version stays in effect."])


# ---------------------------------------------------------------------- collect
def collect_host(cfg: Config, host: Host, run: Runner) -> HostResult:
    hr = HostResult(host=host.name, reachable=True)
    ctx = Ctx(cfg, host)
    if host.type == "fritzbox":
        col = REG["fritzbox"]
        if not (cfg.fritz_user and cfg.fritz_password):
            hr.collectors["fritzbox"] = CollectResult("unavailable", error="FRITZ_USER/FRITZ_PASSWORD missing in .env")
            return hr
        try:
            raw = col.fetch(host.address, host.port, cfg.fritz_user, cfg.fritz_password)
        except PermissionError as e:
            hr.collectors["fritzbox"] = CollectResult("error", error=str(e))
            return hr
        except Exception as e:  # network error
            return HostResult(host=host.name, reachable=False, error=f"TR-064: {e}")
        try:
            hr.collectors["fritzbox"] = CollectResult("ok", col.parse(raw, ctx))
        except ParseError as e:
            hr.collectors["fritzbox"] = CollectResult("error", error=str(e))
        return hr

    for cname in host.collectors:
        col = REG[cname]
        try:
            res = run(host, col.verb)
        except Unreachable as e:
            if not hr.collectors:  # the very first connection fails -> host is down
                return HostResult(host=host.name, reachable=False, error=str(e))
            hr.collectors[cname] = CollectResult("error", error=f"connection lost: {e}")
            continue
        if res.rc == 0:
            try:
                hr.collectors[cname] = CollectResult("ok", col.parse(res.out, ctx))
            except (ParseError, ValueError, KeyError, TypeError) as e:
                hr.collectors[cname] = CollectResult("error", error=f"unreadable output: {e}")
        elif res.unavailable:
            hr.collectors[cname] = CollectResult("unavailable", error=res.err)
        elif res.rc == 64:
            hr.collectors[cname] = CollectResult("error", error="gate rejected the verb - outdated gate on the host? "
                                                                "run install-host.sh again")
        else:
            hr.collectors[cname] = CollectResult("error", error=f"exit {res.rc}: {res.err[:300]}")
    return hr


def _store_results(c: Context, results: list[HostResult]) -> dict[str, Any]:
    t = iso()
    scan_info: dict[str, Any] = {}
    for hr in results:
        meta = c.host_meta.setdefault(hr.host, {"collectors": {}})
        meta["scanned_at"] = t
        meta["reachable"] = hr.reachable
        meta["error"] = hr.error
        info = {"reachable": hr.reachable, "collectors": {}}
        if hr.reachable:
            meta["last_ok"] = t
        for cname, cr in hr.collectors.items():
            meta.setdefault("collectors", {})[cname] = {"status": cr.status, "error": cr.error, "items": len(cr.items),
                                                       "at": t}
            info["collectors"][cname] = {"status": cr.status, "items": len(cr.items)}
            if cr.status != "ok":
                continue
            col = REG[cname]
            write_json(c.cfg.data_dir / "current" / hr.host / f"{cname}.json", {"at": t, "items": cr.items}, mode=0o640)
            if c.git:
                write_json(c.cfg.repo_dir / "snapshots" / hr.host / f"{cname}.json",
                           {"host": hr.host, "collector": cname, "items": [col.stable(i) for i in cr.items]})
        scan_info[hr.host] = info
    # drop hosts that were removed from the configuration from the docs
    known = {h.name for h in c.cfg.hosts}
    for h in [h for h in c.host_meta if h not in known]:
        del c.host_meta[h]
    write_json(c.cfg.data_dir / "hosts.json", c.host_meta, mode=0o640)
    return scan_info


# ---------------------------------------------------------------------- HA sensor, docs, metrics
def sensor_state(c: Context, health_problems: list[str] | None = None) -> tuple[str, dict]:
    st = c.state
    open_ = st.open_findings()
    acked = [f for f in st.findings if f["status"] == ACKED]
    reachable = sum(1 for h in c.cfg.hosts if c.host_meta.get(h.name, {}).get("reachable"))
    problems = health_problems if health_problems is not None else st.meta.get("last_health_problems", [])
    state = "error" if problems or any(f["kind"] == "health" for f in open_) else "drift" if open_ else "ok"
    attrs = {
        "friendly_name": "Homelab-Drift", "icon": "mdi:radar",
        "last_scan": st.meta.get("last_scan"), "last_success": st.meta.get("last_success"),
        "open_findings": len(open_), "open_instant": sum(1 for f in open_ if f["severity"] == INSTANT),
        "acknowledged": len(acked), "pending": len(st.pending), "hosts": len(c.cfg.hosts), "hosts_reachable": reachable,
        "problems": problems[:10], "url": c.cfg.base_url,
        "findings": [f"{f['id']} {f['host']}: {f['title']}" for f in open_[:10]],
    }
    return state, attrs


def publish(c: Context, scan_info: dict | None = None, duration: float = 0.0, ok: bool = True,
            notify: bool = True, ha: HomeAssistant | None = None) -> None:
    """Deliver alerts, set the sensor, write docs and metrics. Errors here must never lose state."""
    ha = ha or HomeAssistant(c.cfg)
    if notify:
        flush_outbox(c.cfg, c.state, ha)
    if c.cfg.ha_token:
        state, attrs = sensor_state(c)
        try:
            ha.set_sensor(state, attrs)
            c.state.meta["ha_sensor_ok"] = True
        except HAError as e:
            c.state.meta["ha_sensor_ok"] = False
            log.warning("HA sensor not updated: %s", e)
    Renderer(c.cfg, c.state, c.changelog, c.notes, REG, c.host_meta, c.git.log() if c.git else []).write()
    if scan_info is None:
        scan_info = {h: {"reachable": m.get("reachable"), "collectors": m.get("collectors", {})} for h, m in c.host_meta.items()}
    write_atomic(c.cfg.www_dir / "metrics", metrics.render(c.cfg, c.state, {"duration": duration, "ok": ok, "hosts": scan_info}))


def _commit_message(s: Summary, pending: list[str] | None = None) -> str:
    if s.first_inventory and not s.confirmed:
        return f"Initial inventory: {', '.join(s.first_inventory)}"
    if s.confirmed:
        head = f"{len(s.confirmed)} change(s): " + "; ".join(f"{f['host']}: {f['title']}" for f in s.confirmed[:3])
        body = "\n".join(f"- [{f['id']}] {f['host']}: {f['title']}" for f in s.confirmed)
        return head[:200] + "\n\n" + body
    if pending:
        keys = [k.replace("|", "/") for k in pending]
        head = f"Observation: {len(keys)} difference(s) not confirmed yet: " + ", ".join(keys[:4])
        return head[:200] + "\n\n" + "\n".join(f"- {k}" for k in keys)
    return "Snapshot updated (docs/info only)"


# ---------------------------------------------------------------------- entry points
def active_maintenance_unit(cfg: Config) -> str | None:
    """First unit from general.pause_while_active that is currently active on the controller, if any."""
    for unit in cfg.pause_while_active:
        try:
            r = subprocess.run(["systemctl", "is-active", "--quiet", unit], timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0:
            return unit
    return None


def run_scan(cfg: Config, run: Runner | None = None, notify: bool = True, ha: HomeAssistant | None = None,
             only_hosts: list[str] | None = None, maintenance: Callable[[Config], str | None] = active_maintenance_unit
             ) -> Summary:
    run = run or ssh_runner(cfg)
    with file_lock(cfg.state_dir / ".lock"):
        t0 = time.monotonic()
        c = open_context(cfg)
        unit = maintenance(cfg) if cfg.pause_while_active else None
        if unit:
            # maintenance window: no scan, no alerts; counts as "alive" for the gap detection
            c.state.meta["last_scan"] = iso()
            c.state.meta["last_pause"] = {"at": iso(), "unit": unit}
            c.state.save()
            log.info("Scan skipped: maintenance unit %s is active", unit)
            return Summary(paused=unit)
        hosts = [h for h in cfg.hosts if not only_hosts or h.name in only_hosts]
        results = [collect_host(cfg, h, run) for h in hosts]
        scan_info = _store_results(c, results)
        eng = Engine(cfg, c.state, c.changelog, c.notes, REG)
        try:
            summary = eng.process(results)
            # a broken annotations YAML is a health problem with an instant alert
            eng._health("annotations", "-", "annotations", c.state.meta.get("annotations_error"),
                        "annotations.yaml is invalid", summary, 1)
            c.state.meta["last_health_problems"] = summary.health_problems
            # show collectors with a health problem (also "tool vanished" or "empty") as down in the metrics
            for key, h in c.state.health.items():
                kind, _, rest = key.partition(":")
                if kind in ("collector", "empty") and h.get("count") and "/" in rest:
                    host, _, cname = rest.partition("/")
                    if host in scan_info:
                        scan_info[host]["collectors"].setdefault(cname, {"items": 0})["status"] = "error"
            if c.git:
                try:
                    c.git.ensure()
                    Renderer(cfg, c.state, c.changelog, c.notes, REG, c.host_meta).write()
                    h = c.git.commit_all(_commit_message(summary, sorted(c.state.pending)))
                    if h:
                        c.state.meta["last_commit"] = h
                except Exception as e:  # git problems must not abort the scan, but must not stay silent either
                    log.error("Snapshot versioning failed: %s", e)
                    summary.health_problems.append(f"git: {e}")
                    eng._notify(INSTANT, "Homelab-Drift: git error", f"Snapshot could not be versioned: {e}", [])
            duration = time.monotonic() - t0
            publish(c, scan_info, duration, ok=not summary.health_problems, notify=notify, ha=ha)
        finally:
            c.state.save()
        log.info("Scan finished in %.1fs: %d confirmed change(s), %d pending, %d problem(s)",
                 time.monotonic() - t0, summary.changes, summary.pending, len(summary.health_problems))
        return summary


def run_digest(cfg: Config, dry_run: bool = False, ha: HomeAssistant | None = None) -> tuple[str, str] | None:
    with file_lock(cfg.state_dir / ".lock"):
        c = open_context(cfg)
        msg = digest(cfg, c.state)
        if dry_run:
            return msg
        if msg:
            c.state.outbox.append({"kind": "digest", "title": msg[0], "message": msg[1], "findings": [],
                                   "created": iso(), "tries": 0})
        try:
            publish(c, notify=True, ha=ha)
        finally:
            c.state.save()
        return msg


def change_acks(cfg: Config, ids: list[str], reason: str = "", until: str | None = None, undo: bool = False,
                item: str | None = None, by: str = "cli", ha: HomeAssistant | None = None) -> list[str]:
    """Acknowledge (or un-acknowledge) findings by ID or by item host/collector/id. Returns result lines."""
    out = []
    with file_lock(cfg.state_dir / ".lock"):
        c = open_context(cfg)
        targets = []
        for i in ids:
            f = c.state.finding(i)
            if not f:
                out.append(f"{i}: unknown")
                continue
            targets.append(f)
        if item:
            parts = item.split("/", 2)
            if len(parts) != 3:
                raise ValueError("--item must look like host/collector/item, e.g. pi/ports/tcp/8091")
            found = c.state.for_item(*parts, statuses=(OPEN,) if not undo else (ACKED,))
            if not found:
                out.append(f"{item}: no {'acknowledged' if undo else 'open'} findings")
            targets += found
        for f in targets:
            if undo:
                if f["status"] != ACKED:
                    out.append(f"{f['id']}: is not acknowledged ({f['status']})")
                    continue
                f["status"] = OPEN
                f.pop("ack", None)
                out.append(f"{f['id']}: open again - {f['title']}")
                c.changelog.append({"host": f["host"], "collector": f["collector"], "item": f["item_id"],
                                    "kind": "ack", "summary": f"Acknowledgement withdrawn: {f['title']}", "finding": f["id"]})
            else:
                if f["status"] != OPEN:
                    out.append(f"{f['id']}: already {f['status']}")
                    continue
                c.state.ack(f, via=by, reason=reason, until=until)
                out.append(f"{f['id']}: acknowledged - {f['title']}")
                c.changelog.append({"host": f["host"], "collector": f["collector"], "item": f["item_id"],
                                    "kind": "ack", "summary": f"Acknowledged: {f['title']}" + (f" ({reason})" if reason else ""),
                                    "finding": f["id"], "status": ACKED})
        try:
            publish(c, notify=False, ha=ha)
        finally:
            c.state.save()
    return out
