"""Listening ports from `ss -tulpnH` with process and exposure.

One item per protocol+port (IPv4 and IPv6 merged). Ports in the ephemeral range (ip_local_port_range) change whenever
the process restarts; they are therefore grouped per process (id ``udp/eph/avahi-daemon``) and the port number does not
count for drift. Exception: docker-proxy, where the port is published on purpose.
"""
from __future__ import annotations

import ipaddress
import re

from . import Collector, Ctx, ParseError

PROC_RE = re.compile(r'\("([^"]+)",pid=(\d+)')
SCOPE_ORDER = ["all", "LAN", "Tailscale", "link-local", "local"]


def scope_of(addr: str, iface: str) -> str:
    if addr in ("*", "0.0.0.0", "::"):
        return "all"
    if iface.startswith("tailscale"):
        return "Tailscale"
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "LAN"
    if ip.is_loopback:
        return "local"
    if ip.is_link_local:
        return "link-local"
    if ip in ipaddress.ip_network("100.64.0.0/10") or (ip.version == 6 and ip in ipaddress.ip_network("fd7a:115c:a1e0::/48")):
        return "Tailscale"
    return "LAN"


def split_local(local: str) -> tuple[str, str, int]:
    host, _, port = local.rpartition(":")
    if not port.isdigit():
        raise ValueError(local)
    iface = ""
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")] + host[host.index("]") + 1:]
    if "%" in host:
        host, iface = host.split("%", 1)
    return host, iface, int(port)


class PortsCollector(Collector):
    name = "ports"
    verb = "ports"
    label = "Port"
    compare = ("exposure", "processes")
    volatile = ("eph_ports",)

    def parse(self, raw: str, ctx: Ctx) -> list[dict]:
        lo, hi = 32768, 60999
        groups: dict[str, dict] = {}
        lines = raw.splitlines()
        if not lines or not lines[0].startswith("#range"):
            raise ParseError("output does not start with #range")
        try:
            lo, hi = (int(x) for x in lines[0].split()[1:3])
        except ValueError:
            pass
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            proto = parts[0]
            if proto not in ("tcp", "udp"):
                continue
            try:
                addr, iface, port = split_local(parts[4])
            except ValueError:
                continue
            procs = sorted({m.group(1) for m in PROC_RE.finditer(line)}) or ["?"]
            ephemeral = lo <= port <= hi and "docker-proxy" not in procs
            key = f"{proto}/eph/{procs[0]}" if ephemeral else f"{proto}/{port}"
            if ctx.ignored("ports", key):
                continue
            g = groups.setdefault(key, {"id": key, "proto": proto, "port": None if ephemeral else port,
                                        "eph_ports": set(), "addresses": set(), "processes": set(),
                                        "scopes": set(), "ephemeral": ephemeral})
            if ephemeral:
                g["eph_ports"].add(port)
            g["addresses"].add(f"[{addr}]" if ":" in addr else addr)
            g["processes"].update(procs)
            g["scopes"].add(scope_of(addr, iface))
        items = []
        for g in groups.values():
            scopes = sorted(g.pop("scopes"), key=SCOPE_ORDER.index)
            g["exposure"] = scopes[0]
            g["scopes"] = scopes
            g["addresses"] = sorted(g["addresses"])
            g["processes"] = sorted(g["processes"])
            g["eph_ports"] = sorted(g["eph_ports"])
            items.append(g)
        return sorted(items, key=lambda i: (i["port"] is None, i["port"] or 0, i["proto"], i["id"]))

    @staticmethod
    def is_public(item: dict) -> bool:
        return item.get("exposure") in ("all", "LAN")

    def describe(self, item: dict) -> str:
        if item.get("ephemeral"):
            return f"Ephemeral {item['proto'].upper()} ports of {', '.join(item['processes'])}"
        return f"Port {item['port']}/{item['proto']}"
