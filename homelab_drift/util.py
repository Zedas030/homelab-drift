"""Small helpers: atomic writes, JSON, locking, time."""
from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Iterator

log = logging.getLogger("homelab_drift")

try:  # not available on Windows development machines
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore


def now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).astimezone()


def iso(t: dt.datetime | None = None) -> str:
    return (t or now()).isoformat(timespec="seconds")


def parse_iso(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s)


def human_duration(seconds: float) -> str:
    """'3 days', '5 hours', '1 minute' - reads well after 'for …'."""
    s = int(max(seconds, 0))
    if s >= 2 * 86400:
        return f"{s // 86400} days"
    if s >= 86400:
        return "1 day"
    if s >= 2 * 3600:
        return f"{s // 3600} hours"
    if s >= 3600:
        return "1 hour"
    m = max(s // 60, 1)
    return "1 minute" if m == 1 else f"{m} minutes"


def short_hash(*parts: Any, n: int = 8) -> str:
    h = hashlib.sha1()
    for p in parts:
        h.update(json.dumps(p, sort_keys=True, ensure_ascii=False, default=str).encode())
        h.update(b"\0")
    return h.hexdigest()[:n]


def _json_default(o: Any) -> Any:
    """YAML turns an unquoted 2026-12-31 into a date; keep such values as ISO strings in JSON."""
    if isinstance(o, (dt.date, dt.datetime)):
        return o.isoformat()
    raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")


def dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False, default=_json_default) + "\n"


def write_atomic(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def write_json(path: Path, obj: Any, mode: int = 0o644) -> None:
    write_atomic(path, dumps(obj), mode)


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except json.JSONDecodeError as e:
        # Never silently discard a broken state file: move it aside and log loudly
        bad = path.with_suffix(path.suffix + f".corrupt-{now():%Y%m%d%H%M%S}")
        os.replace(path, bad)
        log.error("State file %s was corrupt (%s), moved to %s", path, e, bad)
        return default


@contextlib.contextmanager
def file_lock(path: Path, wait: bool = True) -> Iterator[None]:
    """Exclusive lock so that scan, digest and ack never overwrite each other's state."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+") as f:
        if fcntl is not None:
            flags = fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB)
            try:
                fcntl.flock(f.fileno(), flags)
            except BlockingIOError as e:
                raise RuntimeError(f"Another Homelab-Drift run holds the lock {path}") from e
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
