"""systemd services and timers from `systemctl show`.

Collected: enabled or running/failed services and all active/enabled timers. One-shot services that are only started by
a timer are listed with the timer (otherwise they would flip between active and inactive on every run).
"""
from __future__ import annotations

import re

from . import Collector, Ctx, ParseError

ARGV_RE = re.compile(r"argv\[\]=(.*?) ; ignore_errors=")
CAL_RE = re.compile(r"\{ ([A-Za-z]+=[^;]*?) ; next_elapse=[^}]*\}")


def _blocks(text: str) -> list[dict[str, str]]:
    out, cur = [], {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                out.append(cur)
            cur = {}
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            cur[k] = v
    if cur:
        out.append(cur)
    return out


def _run_state(active: str, typ: str) -> str:
    """For drift: on-demand services (dbus, oneshot) come and go - only 'failed' counts for them."""
    st = _state(active)
    if st != "failed" and typ in ("dbus", "oneshot"):
        return "ready"
    return st


def _state(active: str) -> str:
    if active == "failed":
        return "failed"
    if active in ("active", "activating", "reloading", "deactivating"):
        return "active"
    return "inactive"


class SystemdCollector(Collector):
    name = "systemd"
    verb = "systemd"
    label = "Unit"
    volatile = ("state", "active_state", "sub_state")
    compare = ("kind", "unit_file_state", "user", "exec", "run_state", "schedule", "unit")

    def parse(self, raw: str, ctx: Ctx) -> list[dict]:
        if "### SERVICES" not in raw or "### TIMERS" not in raw:
            raise ParseError("output without ### SERVICES / ### TIMERS")
        svc_text, tim_text = raw.split("### SERVICES", 1)[1].split("### TIMERS", 1)
        services = {b["Id"]: b for b in _blocks(svc_text) if b.get("Id")}
        items = []
        for uid, b in services.items():
            ufs = b.get("UnitFileState", "")
            active = b.get("ActiveState", "")
            typ = b.get("Type", "")
            timer_driven = typ == "oneshot" and b.get("TriggeredBy", "").strip().endswith(".timer") \
                and ufs not in ("enabled", "enabled-runtime")
            if timer_driven:
                continue
            if ufs not in ("enabled", "enabled-runtime") and active not in ("active", "activating", "reloading", "failed"):
                continue
            if not b.get("FragmentPath") and active != "failed":
                continue  # transient units (run-*, sessions)
            if ctx.ignored("units", uid):
                continue
            items.append({
                "id": uid, "kind": "service", "description": b.get("Description", ""), "type": typ,
                "user": b.get("User") or "root", "unit_file_state": ufs, "state": _state(active),
                "run_state": _run_state(active, typ), "active_state": active, "sub_state": b.get("SubState", ""),
                "exec": " && ".join(ARGV_RE.findall(b.get("ExecStart", ""))), "fragment": b.get("FragmentPath", ""),
                "schedule": "", "unit": "",
            })
        for b in _blocks(tim_text):
            uid = b.get("Id")
            if not uid or ctx.ignored("units", uid):
                continue
            ufs, active = b.get("UnitFileState", ""), b.get("ActiveState", "")
            if ufs not in ("enabled", "enabled-runtime") and active != "active":
                continue
            sched = CAL_RE.findall(b.get("TimersCalendar", "")) + CAL_RE.findall(b.get("TimersMonotonic", ""))
            target = b.get("Unit", "")
            tsvc = services.get(target, {})
            items.append({
                "id": uid, "kind": "timer", "description": b.get("Description", ""), "type": "",
                "user": tsvc.get("User") or "root", "unit_file_state": ufs, "state": _state(active),
                "run_state": _state(active), "active_state": active, "sub_state": "", "exec": " && ".join(ARGV_RE.findall(tsvc.get("ExecStart", ""))),
                "fragment": "", "schedule": "; ".join(s.strip() for s in sched), "unit": target,
            })
        return sorted(items, key=lambda i: (i["kind"], i["id"]))

    def describe(self, item: dict) -> str:
        return f"{'Timer' if item.get('kind') == 'timer' else 'Service'} {item['id']}"
