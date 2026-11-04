"""Collectors: one module per source. Each collector turns the raw gate output into a list of items.

An item is a dict with a stable key ``id`` plus arbitrary fields. Only the fields in ``Collector.compare`` count for
drift detection; everything else (PIDs, uptimes, disk usage …) is documentation only.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any

from ..config import Config, Host


@dataclass
class Ctx:
    cfg: Config
    host: Host

    def ignored(self, kind: str, value: str) -> bool:
        return any(fnmatch.fnmatchcase(value, pat) for pat in self.cfg.ignore.get(kind, []))


class ParseError(Exception):
    pass


class Collector:
    name: str = ""
    verb: str = ""
    label: str = ""
    compare: tuple[str, ...] = ()
    # fields that change all the time: shown in the docs but kept out of the versioned snapshot (else one commit per scan)
    volatile: tuple[str, ...] = ()

    def parse(self, raw: str, ctx: Ctx) -> list[dict[str, Any]]:
        raise NotImplementedError

    def describe(self, item: dict[str, Any]) -> str:
        """Short name for messages, e.g. 'Port 8091/tcp' or 'Container homeassistant'."""
        return f"{self.label} {item['id']}"

    def stable(self, item: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in item.items() if k not in self.volatile}

    def comparable(self, item: dict[str, Any]) -> dict[str, Any]:
        return {k: item.get(k) for k in self.compare}


def registry() -> dict[str, Collector]:
    from . import cron, docker, fritzbox, nginx, ports, storage, system, systemd, tailscale
    cols = [system.SystemCollector(), docker.DockerCollector(), ports.PortsCollector(), nginx.NginxCollector(),
            cron.CronCollector(), systemd.SystemdCollector(), storage.StorageCollector(),
            tailscale.TailscaleCollector(), fritzbox.FritzboxCollector()]
    return {c.name: c for c in cols}
