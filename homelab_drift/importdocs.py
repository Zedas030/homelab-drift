"""One-time import of notes from an existing hand-written HTML documentation page into a new annotations.yaml.

Recognised are HTML tables whose header starts with Port | Proto | Service (optionally a fourth "exposure" column), and
tables whose first column is Container (optional columns "data"/"volumes" and "network"). Common German column
names (Dienst, Erreichbar, Daten, Netz) are accepted as well. The result is YAML text; it is only ever written to a file
that does not exist yet.
"""
from __future__ import annotations

import datetime as dt
import re
from html.parser import HTMLParser

import yaml

SERVICE_COLS = ("service", "description", "dienst")
EXPOSURE_COLS = ("exposure", "reachable", "erreichbar")
DATA_COLS = ("data", "volumes", "daten")
NET_COLS = ("network", "net", "netz")


class _Tables(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[str]]] = []
        self._rows: list[list[str]] | None = None
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self._rows = []
        elif tag == "tr" and self._rows is not None:
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []
        elif tag == "br" and self._cell is not None:
            self._cell.append(" ")

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append(re.sub(r"\s+", " ", "".join(self._cell)).strip())
            self._cell = None
        elif tag == "tr" and self._row is not None and self._rows is not None:
            self._rows.append(self._row)
            self._row = None
        elif tag == "table" and self._rows is not None:
            self.tables.append(self._rows)
            self._rows = None

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)


def _col(head: list[str], names: tuple[str, ...]) -> int | None:
    return next((i for i, h in enumerate(head) if h in names), None)


def extract(html: str, host: str) -> dict:
    p = _Tables()
    p.feed(html)
    ports: dict[str, str] = {}
    docker: dict[str, str] = {}
    for rows in p.tables:
        if not rows:
            continue
        head = [c.lower() for c in rows[0]]
        if len(head) >= 3 and head[0] == "port" and head[1] == "proto" and head[2] in SERVICE_COLS:
            exp = _col(head, EXPOSURE_COLS)
            for r in rows[1:]:
                if len(r) < 3 or not r[0].strip().isdigit():
                    continue
                note = r[2]
                if exp is not None and len(r) > exp and r[exp]:
                    note += f" (exposure: {r[exp]})"
                for proto in re.split(r"[/,]\s*", r[1].lower()):
                    if proto in ("tcp", "udp"):
                        ports[f"{proto}/{r[0].strip()}"] = note
        elif head and head[0] == "container":
            data, net = _col(head, DATA_COLS), _col(head, NET_COLS)
            for r in rows[1:]:
                if not r or not r[0]:
                    continue
                bits = []
                if data is not None and len(r) > data and r[data] not in ("", "—", "-"):
                    bits.append(f"data: {r[data]}")
                if net is not None and len(r) > net:
                    bits.append(f"network: {r[net]}")
                docker[r[0]] = "imported - " + ", ".join(bits) if bits else "imported"
    out: dict = {host: {}}
    if ports:
        out[host]["ports"] = dict(sorted(ports.items(), key=lambda kv: (int(kv[0].split("/")[1]), kv[0])))
    if docker:
        out[host]["docker"] = docker
    # ephemeral ports (random numbers) are normal: mark them as known
    out["all"] = {"ports": {
        "udp/eph/*": {"note": "ephemeral UDP ports (mDNS/SSDP replies, Tailscale, collectd)", "known": True},
        "tcp/eph/tailscaled": {"note": "Tailscale peer API (random port, tailnet only)", "known": True},
    }}
    return out


HEADER = """# Homelab-Drift - your annotations
# This file is yours: Homelab-Drift only reads it and never writes to it.
# Initial content imported on {date} from {source}.
#
# Layout:   <host or "all">:
#             <collector>:          ports, docker, nginx, cron, systemd, storage, tailscale, fritzbox
#               "<item>": "note"
#               "<item>": {{note: "...", known: true, until: 2026-12-31, reason: "..."}}
# Items are named as shown in the docs (e.g. tcp/8091, homeassistant, nginx.service).
# "known: true" acknowledges permanently (or until the date in "until"): no more alerts.
# * and ? patterns are allowed, e.g. "udp/eph/*".
# Changes take effect with the next scan (or right away: sudo homelab-drift scan).

"""


def to_yaml(data: dict, source: str) -> str:
    body = yaml.safe_dump(data, allow_unicode=True, sort_keys=False, width=140)
    return HEADER.format(date=dt.date.today().isoformat(), source=source) + body
