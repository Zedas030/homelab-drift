"""Load and validate the configuration (YAML) and secrets (.env)."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG = Path(os.environ.get("HOMELAB_DRIFT_CONFIG", "/etc/homelab-drift/config.yaml"))

ALL_COLLECTORS = ["system", "docker", "ports", "nginx", "cron", "systemd", "storage", "tailscale"]


class ConfigError(Exception):
    pass


@dataclass
class Host:
    name: str
    address: str
    type: str = "ssh"  # ssh | fritzbox
    port: int = 22
    user: str | None = None
    description: str = ""
    collectors: list[str] = field(default_factory=lambda: list(ALL_COLLECTORS))


@dataclass
class Config:
    path: Path
    state_dir: Path
    annotations_file: Path
    secrets_file: Path
    base_url: str
    title: str
    ssh_user: str
    ssh_key: Path
    ssh_known_hosts: Path
    ssh_connect_timeout: int
    ssh_command_timeout: int
    hosts: list[Host]
    confirm_after_scans: int
    unreachable_after_scans: int
    scan_interval_minutes: int
    digest_time: str
    storage_warn_percent: int
    storage_crit_percent: int
    ignore: dict[str, list[str]]
    notify_enabled: bool
    notify_service: str
    notify_instant: bool
    notify_digest_empty: bool
    ha_url: str
    ha_token: str | None
    ha_sensor: str
    ha_verify_tls: bool
    fritz_user: str | None
    fritz_password: str | None
    git_enabled: bool
    pause_while_active: list[str] = field(default_factory=list)
    secrets: dict[str, str] = field(default_factory=dict)
    home_url: str = ""  # ui.home_url: optional link back to a house dashboard (empty = no button)
    home_label: str = "Dashboard"

    @property
    def www_dir(self) -> Path:
        return self.state_dir / "www"

    @property
    def repo_dir(self) -> Path:
        return self.state_dir / "repo"

    @property
    def data_dir(self) -> Path:
        return self.state_dir / "state"

    def host(self, name: str) -> Host:
        for h in self.hosts:
            if h.name == name:
                return h
        raise ConfigError(f"Host '{name}' is not configured in {self.path}")


def load_env_file(path: Path) -> dict[str, str]:
    """KEY=VALUE lines, # comments, values optionally quoted."""
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return out
    except PermissionError as e:
        raise ConfigError(f"Secrets file {path} is not readable ({e}). Expected: owner homelab-drift, chmod 600.") from e
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().removeprefix("export ").strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        out[k] = v
    return out


def _get(d: dict, path: str, default: Any) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return default if cur is None else cur


def load(path: Path | str | None = None) -> Config:
    path = Path(path) if path else DEFAULT_CONFIG
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError as e:
        raise ConfigError(f"Configuration {path} not found") from e
    except yaml.YAMLError as e:
        raise ConfigError(f"Configuration {path} is not valid YAML: {e}") from e
    if not isinstance(raw, dict):
        raise ConfigError(f"Configuration {path}: the top level must be a mapping")

    base = path.parent
    def p(v: str) -> Path:
        q = Path(v)
        return q if q.is_absolute() else (base / q)

    state_dir = p(_get(raw, "general.state_dir", "/var/lib/homelab-drift"))
    secrets_file = p(_get(raw, "general.secrets_file", str(base / ".env")))
    secrets = load_env_file(secrets_file)
    def secret(name_key: str, default_name: str) -> str | None:
        name = _get(raw, name_key, default_name)
        return os.environ.get(name) or secrets.get(name) or None

    hosts: list[Host] = []
    names: set[str] = set()
    for i, h in enumerate(_get(raw, "hosts", []) or []):
        if not isinstance(h, dict) or not h.get("name") or not h.get("address"):
            raise ConfigError(f"hosts[{i}]: 'name' and 'address' are required")
        name = str(h["name"])
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,40}", name):
            raise ConfigError(f"hosts[{i}]: invalid name '{name}' (letters, digits, . _ - only)")
        if name in names:
            raise ConfigError(f"hosts: duplicate name '{name}'")
        names.add(name)
        htype = str(h.get("type", "ssh"))
        if htype not in ("ssh", "fritzbox"):
            raise ConfigError(f"hosts[{i}]: type must be ssh or fritzbox")
        cols = h.get("collectors") or (["fritzbox"] if htype == "fritzbox" else list(ALL_COLLECTORS))
        valid = ["fritzbox"] if htype == "fritzbox" else ALL_COLLECTORS
        bad = [c for c in cols if c not in valid]
        if bad:
            raise ConfigError(f"hosts[{i}] ({name}): unknown collectors {bad}, allowed: {valid}")
        hosts.append(Host(name=name, address=str(h["address"]), type=htype, port=int(h.get("port", 22 if htype == "ssh" else 49000)),
                          user=h.get("user"), description=str(h.get("description", "")), collectors=list(cols)))
    if not hosts:
        raise ConfigError("hosts: at least one host is required")

    confirm = int(_get(raw, "drift.confirm_after_scans", 3))
    if confirm < 1:
        raise ConfigError("drift.confirm_after_scans must be >= 1")
    digest_time = str(_get(raw, "notify.digest_time", "19:00"))
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", digest_time):
        raise ConfigError("notify.digest_time must use the format HH:MM")
    home_url = str(_get(raw, "ui.home_url", "")).strip()
    if home_url and not re.match(r"(https?://|/)", home_url):
        raise ConfigError("ui.home_url must start with http://, https:// or /")
    home_label = str(_get(raw, "ui.home_label", "Dashboard")).strip() or "Dashboard"
    ignore_raw = _get(raw, "drift.ignore", {}) or {}
    ignore = {k: [str(x) for x in (v or [])] for k, v in ignore_raw.items()}

    return Config(
        path=path,
        state_dir=state_dir,
        annotations_file=p(_get(raw, "general.annotations", str(base / "annotations.yaml"))),
        secrets_file=secrets_file,
        base_url=str(_get(raw, "general.base_url", "")).rstrip("/") + "/",
        title=str(_get(raw, "general.title", "Homelab-Drift")),
        ssh_user=str(_get(raw, "ssh.user", "drift")),
        ssh_key=p(_get(raw, "ssh.key", str(state_dir / ".ssh/id_ed25519"))),
        ssh_known_hosts=p(_get(raw, "ssh.known_hosts", str(state_dir / ".ssh/known_hosts"))),
        ssh_connect_timeout=int(_get(raw, "ssh.connect_timeout", 10)),
        ssh_command_timeout=int(_get(raw, "ssh.command_timeout", 60)),
        hosts=hosts,
        confirm_after_scans=confirm,
        unreachable_after_scans=int(_get(raw, "drift.unreachable_after_scans", 2)),
        scan_interval_minutes=int(_get(raw, "general.scan_interval_minutes", 15)),
        digest_time=digest_time,
        storage_warn_percent=int(_get(raw, "drift.storage_warn_percent", 85)),
        storage_crit_percent=int(_get(raw, "drift.storage_crit_percent", 95)),
        ignore=ignore,
        notify_enabled=bool(_get(raw, "notify.enabled", True)),
        notify_service=str(_get(raw, "notify.service", "notify.notify")),
        notify_instant=bool(_get(raw, "notify.instant", True)),
        notify_digest_empty=bool(_get(raw, "notify.digest_when_empty", False)),
        ha_url=str(_get(raw, "homeassistant.url", "http://127.0.0.1:8123")).rstrip("/"),
        ha_token=secret("homeassistant.token_env", "HA_TOKEN"),
        ha_sensor=str(_get(raw, "homeassistant.sensor", "sensor.homelab_drift")),
        ha_verify_tls=bool(_get(raw, "homeassistant.verify_tls", True)),
        fritz_user=secret("fritzbox.user_env", "FRITZ_USER"),
        fritz_password=secret("fritzbox.password_env", "FRITZ_PASSWORD"),
        git_enabled=bool(_get(raw, "general.git", True)),
        pause_while_active=[str(u) for u in (_get(raw, "general.pause_while_active", []) or [])],
        secrets=secrets,
        home_url=home_url,
        home_label=home_label,
    )
