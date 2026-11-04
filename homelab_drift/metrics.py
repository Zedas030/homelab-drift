"""Prometheus metrics as a text file (served by nginx at /metrics and scraped by Prometheus)."""
from __future__ import annotations

from .config import Config
from .store import ACKED, OPEN, State
from .util import parse_iso


def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def render(cfg: Config, st: State, scan: dict) -> str:
    """scan: {duration, hosts: {host: {reachable, collectors: {name: {status, items}}}}, ok: bool}"""
    out: list[str] = []

    def metric(name: str, typ: str, help_: str, samples: list[tuple[dict, float]]) -> None:
        out.append(f"# HELP {name} {help_}")
        out.append(f"# TYPE {name} {typ}")
        for labels, val in samples:
            lab = ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items())
            out.append(f"{name}{{{lab}}} {val}" if lab else f"{name} {val}")

    def ts(key: str) -> float:
        v = st.meta.get(key)
        return parse_iso(v).timestamp() if v else 0

    metric("homelab_drift_last_scan_timestamp_seconds", "gauge", "Time of the last scan", [({}, ts("last_scan"))])
    metric("homelab_drift_last_success_timestamp_seconds", "gauge", "Time of the last scan without a health problem",
           [({}, ts("last_success"))])
    metric("homelab_drift_last_digest_timestamp_seconds", "gauge", "Time of the last daily digest", [({}, ts("last_digest"))])
    metric("homelab_drift_scan_duration_seconds", "gauge", "Duration of the last scan", [({}, round(scan.get("duration", 0), 3))])
    metric("homelab_drift_scan_ok", "gauge", "1 if the last scan ran without a health problem", [({}, 1 if scan.get("ok") else 0)])
    metric("homelab_drift_scans_total", "counter", "Number of scans since installation", [({}, int(st.meta.get("scans", 0)))])
    hosts = scan.get("hosts", {})
    metric("homelab_drift_host_reachable", "gauge", "1 if the host was reachable via SSH",
           [({"host": h}, 1 if d.get("reachable") else 0) for h, d in sorted(hosts.items())])
    up, items = [], []
    for h, d in sorted(hosts.items()):
        for c, r in sorted((d.get("collectors") or {}).items()):
            if r.get("status") == "unavailable":
                continue
            up.append(({"host": h, "collector": c}, 1 if r.get("status") == "ok" else 0))
            items.append(({"host": h, "collector": c}, r.get("items", 0)))
    metric("homelab_drift_collector_up", "gauge", "1 if the collector returned data", up)
    metric("homelab_drift_collector_items", "gauge", "Number of collected items per collector", items)
    counts: dict[tuple[str, str], int] = {}
    for f in st.findings:
        if f["status"] in (OPEN, ACKED):
            counts[(f["severity"], f["status"])] = counts.get((f["severity"], f["status"]), 0) + 1
    samples = [({"severity": sev, "status": stt}, counts.get((sev, stt), 0))
               for sev in ("instant", "digest") for stt in (OPEN, ACKED)]
    metric("homelab_drift_findings", "gauge", "Findings by severity and status", samples)
    metric("homelab_drift_pending_observations", "gauge", "Differences still waiting for confirmation (N scans)",
           [({}, len(st.pending))])
    metric("homelab_drift_outbox_messages", "gauge", "Notifications that could not be delivered yet", [({}, len(st.outbox))])
    metric("homelab_drift_notify_failures_total", "counter", "Failed delivery attempts",
           [({}, int(st.meta.get("notify_failures_total", 0)))])
    metric("homelab_drift_notify_sent_total", "counter", "Delivered notifications", [({}, int(st.meta.get("notify_sent_total", 0)))])
    return "\n".join(out) + "\n"
