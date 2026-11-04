"""Your annotations (annotations.yaml). The tool only reads this file and never writes to it.

Layout::

    pi:                      # host name from config.yaml, or "all" for every host
      _host: "Note about the host"
      ports:                 # collector name
        tcp/8091: "Wiki (nginx)"                     # short form: just a note
        tcp/18999:                                   # long form
          note: "Test service XY"
          known: true                                # acknowledged: no more alerts
          until: 2026-12-31                          # optional: acknowledgement expires
          reason: "only until the end of the year"
      docker:
        homeassistant: "Home Assistant"
    all:
      ports:
        "udp/eph/*": {known: true, note: "ephemeral ports"}   # * and ? patterns are allowed
"""
from __future__ import annotations

import datetime as dt
import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ALL = "all"


@dataclass
class Note:
    note: str = ""
    known: bool = False
    until: dt.date | None = None
    reason: str = ""

    @property
    def documented(self) -> bool:
        return bool(self.note) or self.known

    def acknowledged(self, today: dt.date | None = None) -> bool:
        if not self.known:
            return False
        return self.until is None or (today or dt.date.today()) <= self.until


@dataclass
class Annotations:
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def host_note(self, host: str) -> str:
        h = self.data.get(host) or {}
        return str(h.get("_host", "")) if isinstance(h, dict) else ""

    def get(self, host: str, collector: str, item_id: str) -> Note:
        note = Note()
        for scope in (ALL, host):  # host-specific entries override "all"
            sect = ((self.data.get(scope) or {}).get(collector) or {}) if isinstance(self.data.get(scope), dict) else {}
            if not isinstance(sect, dict):
                continue
            # exact matches last so that they override patterns
            keys = [k for k in sect if k != item_id and any(c in str(k) for c in "*?[") and fnmatch.fnmatchcase(item_id, str(k))]
            if item_id in sect:
                keys.append(item_id)
            for k in keys:
                note = _merge(note, sect[k])
        return note


def _merge(note: Note, v: Any) -> Note:
    if isinstance(v, str):
        return Note(note=v, known=note.known, until=note.until, reason=note.reason)
    if not isinstance(v, dict):
        return note
    until = v.get("until", note.until)
    if isinstance(until, str):
        try:
            until = dt.date.fromisoformat(until)
        except ValueError:
            until = None
    if isinstance(until, dt.datetime):
        until = until.date()
    return Note(note=str(v.get("note", note.note) or ""), known=bool(v.get("known", note.known)),
                until=until, reason=str(v.get("reason", note.reason) or ""))


class AnnotationsError(Exception):
    pass


def load(path: Path, known_hosts: list[str], known_collectors: list[str]) -> Annotations:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return Annotations({}, [f"{path} does not exist yet - no annotations"])
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as e:
        raise AnnotationsError(f"{path} is not valid YAML: {e}") from e
    if not isinstance(data, dict):
        raise AnnotationsError(f"{path}: the top level must be a mapping (host: ...)")
    warnings = []
    for host, sect in data.items():
        if host != ALL and host not in known_hosts:
            warnings.append(f"Annotations: host '{host}' is not in the configuration")
        if not isinstance(sect, dict):
            warnings.append(f"Annotations: '{host}' is not a mapping")
            continue
        for col in sect:
            if col != "_host" and col not in known_collectors:
                warnings.append(f"Annotations: '{host}.{col}' is not a collector ({', '.join(known_collectors)})")
    return Annotations(data, warnings)
