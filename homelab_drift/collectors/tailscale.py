"""Tailscale status: this node (running? which IPs?) and the devices in the tailnet."""
from __future__ import annotations

import json

from . import Collector, Ctx, ParseError


class TailscaleCollector(Collector):
    name = "tailscale"
    verb = "tailscale"
    label = "Tailnet device"
    # online/offline changes constantly (phones sleep) -> documentation only, no drift
    compare = ("backend_state", "ips", "os")
    volatile = ("online", "last_seen", "version")

    def parse(self, raw: str, ctx: Ctx) -> list[dict]:
        try:
            d = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ParseError(f"tailscale status returned no JSON: {e}") from e
        me = d.get("Self") or {}
        items = [{
            "id": "self", "hostname": me.get("HostName", ""), "dns_name": (me.get("DNSName") or "").rstrip("."),
            "backend_state": d.get("BackendState", ""), "ips": sorted(d.get("TailscaleIPs") or []),
            "os": me.get("OS", ""), "online": bool(me.get("Online", True)), "last_seen": "",
            "version": (d.get("Version") or "").split("-")[0],
        }]
        for p in (d.get("Peer") or {}).values():
            # iOS often reports HostName "localhost" -> the MagicDNS name is unique
            name = ((p.get("DNSName") or "").split(".")[0] or p.get("HostName") or "").lower()
            if not name or ctx.ignored("tailscale_peers", name):
                continue
            items.append({
                "id": name, "hostname": p.get("HostName", ""), "dns_name": (p.get("DNSName") or "").rstrip("."),
                "backend_state": "", "ips": sorted(p.get("TailscaleIPs") or []), "os": p.get("OS", ""),
                "online": bool(p.get("Online")), "last_seen": (p.get("LastSeen") or "")[:16], "version": "",
            })
        return sorted(items, key=lambda i: (i["id"] != "self", i["id"]))

    def describe(self, item: dict) -> str:
        return "Tailscale on this host" if item["id"] == "self" else f"Tailnet device {item['id']}"
