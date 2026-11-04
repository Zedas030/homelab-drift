from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from homelab_drift import config  # noqa: E402
from homelab_drift.collectors import Ctx  # noqa: E402

FIX = Path(__file__).parent / "fixtures"
VERBS = ["system", "docker", "ports", "nginx", "cron", "systemd", "storage", "tailscale"]


def raw(verb: str, host: str = "pi") -> str:
    return (FIX / host / f"{verb}.out").read_text(encoding="utf-8")


class FakeHA:
    def __init__(self, fail: bool = False):
        self.sent: list[tuple[str, str]] = []
        self.sensor: tuple[str, dict] | None = None
        self.fail = fail

    def notify(self, title, message, url="", tag=""):
        from homelab_drift.notify import HAError
        if self.fail:
            raise HAError("HA aus")
        self.sent.append((title, message))

    def set_sensor(self, state, attrs):
        from homelab_drift.notify import HAError
        if self.fail:
            raise HAError("HA aus")
        self.sensor = (state, attrs)


def write_cfg(tmp: Path, **over) -> Path:
    c = yaml.safe_load((ROOT / "config" / "config.example.yaml").read_text(encoding="utf-8"))
    c["general"].update(state_dir=str(tmp / "state"), annotations=str(tmp / "annotations.yaml"),
                        secrets_file=str(tmp / ".env"), base_url="http://drift.example.local:8097/")
    c["hosts"] = [{"name": "pi", "address": "127.0.0.1"}]
    for k, v in over.items():
        sect, _, key = k.partition("__")
        if key:
            c.setdefault(sect, {})[key] = v
        else:
            c[sect] = v
    p = tmp / "config.yaml"
    p.write_text(yaml.safe_dump(c, allow_unicode=True), encoding="utf-8")
    if not (tmp / ".env").exists():
        (tmp / ".env").write_text("HA_TOKEN=test-token\n", encoding="utf-8")
    return p


@pytest.fixture
def cfg(tmp_path):
    return config.load(write_cfg(tmp_path))


@pytest.fixture
def ctx(cfg):
    return Ctx(cfg, cfg.hosts[0])


@pytest.fixture
def outputs():
    return {"pi": {v: raw(v) for v in VERBS}}
