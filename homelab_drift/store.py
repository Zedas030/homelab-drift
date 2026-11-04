"""State on disk: baseline, pending observations, findings, health, changelog, outbox."""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import iso, now, parse_iso, read_json, write_json

OPEN, ACKED, CLOSED = "open", "acknowledged", "closed"
KEEP_CLOSED_DAYS = 90


@dataclass
class State:
    path: Path
    baseline: dict[str, dict[str, dict[str, dict]]] = field(default_factory=dict)
    pending: dict[str, dict] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    health: dict[str, dict] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)
    outbox: list[dict] = field(default_factory=list)

    # --- load/save -------------------------------------------------------
    @classmethod
    def load(cls, data_dir: Path) -> "State":
        p = data_dir / "state.json"
        d = read_json(p, {})
        return cls(path=p, baseline=d.get("baseline", {}), pending=d.get("pending", {}), findings=d.get("findings", []),
                   health=d.get("health", {}), meta=d.get("meta", {"seq": 0}), outbox=d.get("outbox", []))

    def save(self) -> None:
        cutoff = now() - dt.timedelta(days=KEEP_CLOSED_DAYS)
        self.findings = [f for f in self.findings
                         if f["status"] != CLOSED or parse_iso(f.get("closed_at") or f["created"]) > cutoff]
        write_json(self.path, {"baseline": self.baseline, "pending": self.pending, "findings": self.findings,
                               "health": self.health, "meta": self.meta, "outbox": self.outbox}, mode=0o640)

    # --- findings --------------------------------------------------------
    def next_id(self) -> str:
        self.meta["seq"] = int(self.meta.get("seq", 0)) + 1
        return f"D-{self.meta['seq']:04d}"

    def finding(self, fid: str) -> dict | None:
        fid = fid.upper()
        if fid.isdigit():
            fid = f"D-{int(fid):04d}"
        return next((f for f in self.findings if f["id"] == fid), None)

    def open_findings(self, include_acked: bool = False) -> list[dict]:
        ok = (OPEN, ACKED) if include_acked else (OPEN,)
        return [f for f in self.findings if f["status"] in ok]

    def for_item(self, host: str, collector: str, item_id: str, statuses=(OPEN, ACKED)) -> list[dict]:
        return [f for f in self.findings if f["host"] == host and f["collector"] == collector
                and f["item_id"] == item_id and f["status"] in statuses]

    def health_finding(self, key: str) -> dict | None:
        return next((f for f in self.findings if f.get("health_key") == key and f["status"] in (OPEN, ACKED)), None)

    def close(self, f: dict, reason: str) -> None:
        f["status"] = CLOSED
        f["closed_at"] = iso()
        f["closed_reason"] = reason

    def ack(self, f: dict, via: str, reason: str = "", until: str | None = None, by: str = "") -> None:
        f["status"] = ACKED
        f["ack"] = {"at": iso(), "via": via, "reason": reason, "until": until, "by": by}


class Changelog:
    def __init__(self, data_dir: Path):
        self.path = data_dir / "changelog.jsonl"

    def append(self, entry: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps({"ts": iso(), **entry}, ensure_ascii=False, sort_keys=True) + "\n")

    def read(self, limit: int | None = None) -> list[dict]:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        out.reverse()  # newest first
        return out[:limit] if limit else out
