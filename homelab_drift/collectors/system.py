"""Basic host facts: name, kernel, OS, boot time (to detect reboots)."""
from __future__ import annotations

import datetime as dt

from . import Collector, Ctx, ParseError


class SystemCollector(Collector):
    name = "system"
    verb = "system"
    label = "System"
    compare = ("hostname", "kernel", "os", "boot_time")
    volatile = ("uptime_s",)

    def parse(self, raw: str, ctx: Ctx) -> list[dict]:
        kv = {}
        for line in raw.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()
        if "hostname" not in kv:
            raise ParseError("output contains no hostname")
        boot = ""
        if kv.get("boot_time", "").isdigit():
            boot = dt.datetime.fromtimestamp(int(kv["boot_time"]), dt.timezone.utc).astimezone().isoformat(timespec="minutes")
        mem_gb = round(int(kv["mem_kb"]) / 1024 / 1024, 1) if kv.get("mem_kb", "").isdigit() else None
        return [{
            "id": "system",
            "hostname": kv.get("hostname"),
            "kernel": kv.get("kernel"),
            "arch": kv.get("arch"),
            "os": kv.get("os"),
            "boot_time": boot,
            "uptime_s": float(kv["uptime"]) if kv.get("uptime") else None,
            "cpus": int(kv["cpus"]) if kv.get("cpus", "").isdigit() else None,
            "mem_gb": mem_gb,
            "gate": kv.get("gate"),
        }]

    def describe(self, item: dict) -> str:
        return "System facts"
