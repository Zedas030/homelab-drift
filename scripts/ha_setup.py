"""Create the dead man's switch automation in Home Assistant (REST API, idempotent).

Usage (install.sh --ha-setup does this):  python scripts/ha_setup.py /etc/homelab-drift/config.yaml
The notify service and the sensor are taken from config.yaml.
"""
from __future__ import annotations

import sys
from pathlib import Path

import requests
import yaml

from homelab_drift.config import load

AUTOMATION_ID = "homelab_drift_dead_mans_switch"


def main() -> int:
    cfg = load(sys.argv[1] if len(sys.argv) > 1 else None)
    if not cfg.ha_token:
        print("HA_TOKEN missing in .env - automation not created.")
        return 1
    text = (Path(__file__).resolve().parent.parent / "config" / "ha-automation.yaml").read_text(encoding="utf-8")
    text = text.replace("notify.mobile_app_phone", cfg.notify_service).replace("sensor.homelab_drift", cfg.ha_sensor)
    body = yaml.safe_load(text)
    h = {"Authorization": f"Bearer {cfg.ha_token}", "Content-Type": "application/json"}
    r = requests.post(f"{cfg.ha_url}/api/config/automation/config/{AUTOMATION_ID}", json=body, headers=h, timeout=20,
                      verify=cfg.ha_verify_tls)
    if r.status_code >= 300:
        print(f"Error {r.status_code}: {r.text[:300]}")
        return 1
    print(f"Automation {AUTOMATION_ID} created/updated (notifications via {cfg.notify_service}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
