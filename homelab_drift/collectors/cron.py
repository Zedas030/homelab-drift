"""Cron jobs: /etc/crontab, /etc/cron.d/*, /etc/cron.{hourly,daily,weekly,monthly}/* and the crontabs of all users."""
from __future__ import annotations

import os
import re

from ..util import short_hash
from . import Collector, Ctx

ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
SPECIAL = ("@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly")


def _split(line: str, with_user: bool) -> tuple[str, str, str] | None:
    parts = line.split()
    if not parts:
        return None
    if parts[0] in SPECIAL:
        n_sched = 1
    elif len(parts) >= 5:
        n_sched = 5
    else:
        return None
    need = n_sched + (2 if with_user else 1)
    if len(parts) < need:
        return None
    sched = " ".join(parts[:n_sched])
    rest = line.split(None, n_sched)[n_sched]
    if with_user:
        user, cmd = rest.split(None, 1)
    else:
        user, cmd = "", rest
    return sched, user, cmd.strip()


class CronCollector(Collector):
    name = "cron"
    verb = "cron"
    label = "Cron job"
    compare = ("schedule", "user", "command")

    def parse(self, raw: str, ctx: Ctx) -> list[dict]:
        items: dict[str, dict] = {}
        source, user_of_file, with_user = None, "", True

        def add(sched: str, user: str, cmd: str, src: str) -> None:
            short = src.replace("/etc/", "").replace("/var/spool/cron/crontabs/", "crontab:")
            iid = f"{user}:{short}:{short_hash(cmd, n=6)}"
            n = 2
            while iid in items:
                iid = f"{user}:{short}:{short_hash(cmd, n=6)}#{n}"
                n += 1
            if ctx.ignored("cron", cmd) or ctx.ignored("cron", iid):
                return
            items[iid] = {"id": iid, "schedule": sched, "user": user, "command": cmd, "source": src}

        for line in raw.splitlines():
            if line.startswith("### FILE "):
                source, with_user, user_of_file = line[9:].strip(), True, ""
                continue
            if line.startswith("### USER "):
                user_of_file = line[9:].strip()
                source, with_user = f"crontab:{user_of_file}", False
                continue
            if line.startswith("### RUNPARTS "):
                _, _, period, name = line.split(" ", 3)
                add(f"@{period}", "root", f"/etc/cron.{period}/{name}", f"/etc/cron.{period}")
                source = None
                continue
            if source is None:
                continue
            s = line.strip()
            if not s or s.startswith("#") or ENV_RE.match(s):
                continue
            parsed = _split(s, with_user)
            if not parsed:
                continue
            sched, user, cmd = parsed
            add(sched, user or user_of_file, cmd, source)
        return sorted(items.values(), key=lambda i: i["id"])

    def describe(self, item: dict) -> str:
        cmd = item.get("command", "")
        cmd = cmd if len(cmd) <= 60 else cmd[:57] + "…"
        return f"Cron job ({item.get('user')}, {item.get('schedule')}, {os.path.basename(item.get('source', ''))}): {cmd}"
