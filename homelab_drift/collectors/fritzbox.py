"""Optional: device list of an AVM FRITZ!Box via TR-064 (X_AVM-DE_GetHostListPath, read-only).

Runs directly from the controller (no SSH). Credentials: FRITZ_USER / FRITZ_PASSWORD in the .env. The router user only
needs the "FRITZ!Box settings" permission; TR-064 must be enabled under Home Network -> Network -> Network Settings
("Allow access for applications").
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from . import Collector, Ctx, ParseError

SERVICE = "urn:dslforum-org:service:Hosts:1"
ACTION = "X_AVM-DE_GetHostListPath"
ENVELOPE = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    f'<s:Body><u:{ACTION} xmlns:u="{SERVICE}"/></s:Body></s:Envelope>'
)


class FritzboxCollector(Collector):
    name = "fritzbox"
    verb = ""  # no gate verb: plain HTTP
    label = "Device"
    compare = ("name",)
    volatile = ("active", "ip")

    def fetch(self, address: str, port: int, user: str, password: str, timeout: int = 20) -> str:
        import requests
        from requests.auth import HTTPDigestAuth
        base = f"http://{address}:{port}"
        auth = HTTPDigestAuth(user, password)
        r = requests.post(f"{base}/upnp/control/hosts", data=ENVELOPE.encode(), auth=auth, timeout=timeout,
                          headers={"Content-Type": 'text/xml; charset="utf-8"', "SOAPACTION": f"{SERVICE}#{ACTION}"})
        if r.status_code == 401:
            raise PermissionError("FRITZ!Box rejected the login (check FRITZ_USER/FRITZ_PASSWORD)")
        r.raise_for_status()
        m = re.search(r"<NewX_AVM-DE_HostListPath>([^<]+)</NewX_AVM-DE_HostListPath>", r.text)
        if not m:
            raise ParseError("response without HostListPath")
        r2 = requests.get(base + m.group(1), timeout=timeout)
        r2.raise_for_status()
        return r2.text

    def parse(self, raw: str, ctx: Ctx) -> list[dict]:
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as e:
            raise ParseError(f"host list is not XML: {e}") from e
        items = {}
        for it in root.iter("Item"):
            g = {c.tag: (c.text or "").strip() for c in it}
            mac = g.get("MACAddress", "").lower()
            if not mac or ctx.ignored("fritz_devices", mac) or ctx.ignored("fritz_devices", g.get("HostName", "")):
                continue
            items[mac] = {"id": mac, "name": g.get("HostName", ""), "ip": g.get("IPAddress", ""),
                          "interface": g.get("InterfaceType", "") or ("WLAN" if g.get("X_AVM-DE_Speed") else ""),
                          "active": g.get("Active") == "1"}
        return sorted(items.values(), key=lambda i: (i["name"].lower(), i["id"]))

    def describe(self, item: dict) -> str:
        return f"Device {item.get('name') or item['id']} ({item['id']})"
