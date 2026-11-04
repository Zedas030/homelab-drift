"""Home Assistant: alerts through a notify service and a status sensor via the REST API.

Alerts go through an outbox kept in the state: if HA is unreachable they stay queued and are sent with the next scan
(for at most 48 h; after that they are dropped and the drop is logged). Nothing is lost silently.
"""
from __future__ import annotations

import datetime as dt
from typing import Any

import requests

from .config import Config
from .engine import ACK_HINT, INSTANT
from .store import State
from .util import log, now, parse_iso

MAX_AGE_H = 48


class HAError(Exception):
    pass


class HomeAssistant:
    def __init__(self, cfg: Config, session: Any = None):
        self.cfg = cfg
        self.s = session or requests.Session()

    def _headers(self) -> dict:
        if not self.cfg.ha_token:
            raise HAError("HA_TOKEN missing in .env")
        return {"Authorization": f"Bearer {self.cfg.ha_token}", "Content-Type": "application/json"}

    def _post(self, path: str, payload: dict) -> Any:
        try:
            r = self.s.post(f"{self.cfg.ha_url}{path}", json=payload, headers=self._headers(), timeout=15,
                            verify=self.cfg.ha_verify_tls)
        except requests.RequestException as e:
            raise HAError(f"Home Assistant unreachable: {e}") from e
        if r.status_code >= 300:
            raise HAError(f"Home Assistant answered {r.status_code} to {path}: {r.text[:200]}")
        return r

    def ping(self) -> str:
        """GET /api/ - checks reachability and token without changing anything."""
        try:
            r = self.s.get(f"{self.cfg.ha_url}/api/", headers=self._headers(), timeout=10, verify=self.cfg.ha_verify_tls)
        except requests.RequestException as e:
            raise HAError(f"Home Assistant unreachable: {e}") from e
        if r.status_code != 200:
            raise HAError(f"Home Assistant answered {r.status_code} (invalid token?)")
        return r.json().get("message", "ok")

    def notify(self, title: str, message: str, url: str = "", tag: str = "") -> None:
        domain, _, service = self.cfg.notify_service.partition(".")
        data: dict[str, Any] = {}
        if url:
            data.update(url=url, clickAction=url)  # iOS: url, Android: clickAction
        if tag:
            data["tag"] = tag
        payload: dict[str, Any] = {"title": title, "message": message}
        if data:
            payload["data"] = data
        self._post(f"/api/services/{domain}/{service}", payload)

    def set_sensor(self, state: str, attributes: dict) -> None:
        self._post(f"/api/states/{self.cfg.ha_sensor}", {"state": state, "attributes": attributes})


def _bundle(outbox: list[dict]) -> list[dict]:
    """Merge instant alerts with the same title (= same host) into one push: one event, one notification."""
    out: list[dict] = []
    for msg in outbox:
        prev = out[-1] if out else None
        if prev and prev["kind"] == msg["kind"] == INSTANT and prev["title"] == msg["title"]:
            a, b = prev["message"].split(ACK_HINT)[0], msg["message"].split(ACK_HINT)[0]
            ids = prev.get("findings", []) + msg.get("findings", [])
            hinted = ACK_HINT in prev["message"] or ACK_HINT in msg["message"]
            prev.update(message=f"{a}\n{b}" + (f"{ACK_HINT} {' '.join(ids)} - or document it in annotations.yaml."
                                               if hinted else ""),
                        findings=ids, tries=max(prev.get("tries", 0), msg.get("tries", 0)),
                        created=min(prev["created"], msg["created"]))
        else:
            out.append(dict(msg))
    return out


def flush_outbox(cfg: Config, st: State, ha: HomeAssistant | None = None) -> tuple[int, int]:
    """Send the outbox. Returns (sent, failed)."""
    if not st.outbox:
        return 0, 0
    if not cfg.notify_enabled:
        log.info("Notifications disabled, %d dropped", len(st.outbox))
        st.outbox.clear()
        return 0, 0
    ha = ha or HomeAssistant(cfg)
    sent = failed = 0
    keep = []
    for msg in _bundle(st.outbox):
        url = cfg.base_url + (f"index.html#{msg['findings'][0]}" if msg.get("findings") else "")
        try:
            ha.notify(msg["title"], msg["message"], url=url if cfg.base_url.strip("/") else "",
                      tag=f"homelab-drift-{msg['kind']}")
            sent += 1
            log.info("Notification sent: %s", msg["title"])
        except HAError as e:
            failed += 1
            msg["tries"] = int(msg.get("tries", 0)) + 1
            msg["last_error"] = str(e)
            if now() - parse_iso(msg["created"]) > dt.timedelta(hours=MAX_AGE_H):
                log.error("Notification dropped after %d h: %s - %s", MAX_AGE_H, msg["title"], e)
            else:
                log.warning("Notification not delivered (attempt %d), kept in the outbox: %s", msg["tries"], e)
                keep.append(msg)
    st.outbox = keep
    st.meta["notify_failures_total"] = int(st.meta.get("notify_failures_total", 0)) + failed
    st.meta["notify_sent_total"] = int(st.meta.get("notify_sent_total", 0)) + sent
    return sent, failed
