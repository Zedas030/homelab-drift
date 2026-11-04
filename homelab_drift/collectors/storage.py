"""Mounts and disk space from `findmnt -J --real`."""
from __future__ import annotations

import json

from . import Collector, Ctx, ParseError

SKIP_FS = {"squashfs", "overlay", "tmpfs", "devtmpfs", "ramfs", "autofs", "fuse.portal", "fuse.gvfsd-fuse", "nsfs"}


def _flatten(nodes: list[dict]):
    for n in nodes or []:
        yield n
        yield from _flatten(n.get("children") or [])


class StorageCollector(Collector):
    name = "storage"
    verb = "storage"
    label = "Mount"
    # usage itself does not count, only crossing a threshold (level)
    compare = ("source", "fstype", "level")
    volatile = ("used", "avail", "use_percent")

    def parse(self, raw: str, ctx: Ctx) -> list[dict]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ParseError(f"findmnt returned no JSON: {e}") from e
        warn, crit = ctx.cfg.storage_warn_percent, ctx.cfg.storage_crit_percent
        items = []
        for n in _flatten(data.get("filesystems", [])):
            target, fstype = n.get("target", ""), n.get("fstype", "")
            if fstype in SKIP_FS or target.startswith(("/snap/", "/var/lib/docker/", "/run/")) or ctx.ignored("mounts", target):
                continue
            size, used, avail = (int(n.get(k) or 0) for k in ("size", "used", "avail"))
            pct = round(100 * used / (used + avail), 1) if used + avail else 0.0
            level = "critical" if pct >= crit else "full" if pct >= warn else "ok"
            items.append({"id": target, "source": n.get("source", ""), "fstype": fstype, "options": n.get("options", ""),
                          "size": size, "used": used, "avail": avail, "use_percent": pct, "level": level})
        return sorted(items, key=lambda i: i["id"])

    def describe(self, item: dict) -> str:
        return f"Mount {item['id']}"
