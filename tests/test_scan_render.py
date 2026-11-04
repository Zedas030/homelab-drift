"""Full scan cycle with simulated SSH/HA: snapshot, git, docs, metrics, sensor, acknowledgement."""
import json
import re
import shutil
import subprocess

import pytest

from conftest import FakeHA, raw, write_cfg
from homelab_drift import config, scan
from homelab_drift.transport import Result, Unreachable, fake_runner

PORT = 'tcp LISTEN 0 4096 0.0.0.0:18999 0.0.0.0:* users:(("docker-proxy",pid=999,fd=8))\n'
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def run(cfg, outputs, ha, n=1):
    s = None
    for _ in range(n):
        s = scan.run_scan(cfg, run=fake_runner(outputs), ha=ha)
    return s


def git_log(repo, fmt="--oneline"):
    return subprocess.run(["git", "-C", str(repo), "log", fmt], capture_output=True, text=True, encoding="utf-8").stdout


@needs_git
def test_full_cycle(cfg, outputs, tmp_path):
    (tmp_path / "annotations.yaml").write_text('pi:\n  _host: "Test host"\n  ports:\n    tcp/8091: "Wiki"\n', encoding="utf-8")
    ha = FakeHA()
    run(cfg, outputs, ha)
    www = cfg.www_dir
    assert {"index.html", "ports.html", "changelog.html", "host-pi.html", "metrics"} <= {p.name for p in www.iterdir()}
    assert any(p.name.startswith("service-pi-docker-homeassistant") for p in www.iterdir())
    ports_html = (www / "ports.html").read_text(encoding="utf-8")
    assert "Wiki" in ports_html and "undocumented" in ports_html
    assert ">Container uptime-kuma<" in ports_html  # port -> service via docker-proxy, the running container wins
    assert ">Container uptime-kuma-old-v1<" not in ports_html
    assert ha.sensor[0] == "ok" and ha.sensor[1]["open_findings"] == 0
    repo = cfg.repo_dir
    assert (repo / "snapshots" / "pi" / "ports.json").exists() and (repo / "docs" / "pi.md").exists()
    assert (repo / "CHANGELOG.md").read_text(encoding="utf-8").count("Initial inventory") == 8
    log1 = git_log(repo)
    assert len(log1.splitlines()) == 1 and "Initial inventory" in log1

    # unchanged second scan -> no new commit (docs without timestamps/uptimes)
    run(cfg, outputs, ha)
    assert git_log(repo) == log1

    # new port -> instant alert after 3 scans, sensor "drift"
    outputs["pi"]["ports"] = raw("ports") + PORT
    s = run(cfg, outputs, ha, 3)
    assert [f["id"] for f in s.confirmed] == ["D-0001"]
    assert len(ha.sent) == 1 and "Port 18999/tcp is new" in ha.sent[0][1]
    assert ha.sensor[0] == "drift" and ha.sensor[1]["open_instant"] == 1
    assert 'id="D-0001"' in (www / "index.html").read_text(encoding="utf-8")
    log3 = git_log(repo, "--format=%s")
    assert "1 change(s): pi: Port 18999/tcp is new" in log3 and "Observation:" in log3

    # acknowledge via the CLI function -> nothing open, changelog entry
    out = scan.change_acks(cfg, ["1"], reason="test container", ha=ha)
    assert out == ["D-0001: acknowledged - Port 18999/tcp is new (exposed: all, process docker-proxy)"]
    run(cfg, outputs, ha)
    assert ha.sensor[0] == "ok" and len(ha.sent) == 1
    assert "Acknowledged: Port 18999" in (www / "changelog.html").read_text(encoding="utf-8")
    assert scan.change_acks(cfg, ["D-0001"], undo=True, ha=ha)[0].startswith("D-0001: open again")
    assert scan.change_acks(cfg, [], item="pi/ports/tcp/18999", ha=ha)[0].startswith("D-0001: acknowledged")

    # port gone again -> "removed" finding in the digest
    outputs["pi"]["ports"] = raw("ports")
    s = run(cfg, outputs, ha, 3)
    assert s.confirmed[0]["kind"] == "removed" and s.confirmed[0]["severity"] == "digest"
    title, msg = scan.run_digest(cfg, ha=ha)
    assert "Port 18999/tcp is gone" in msg and ha.sent[-1][0] == title

    metrics = (www / "metrics").read_text(encoding="utf-8")
    assert 'homelab_drift_collector_up{host="pi",collector="docker"} 1' in metrics
    assert re.search(r"^homelab_drift_last_scan_timestamp_seconds \d+", metrics, re.M)
    assert 'homelab_drift_findings{severity="digest",status="open"} 1' in metrics


def test_instant_alerts_of_one_host_are_bundled():
    from homelab_drift.engine import ACK_HINT
    from homelab_drift.notify import _bundle
    hint = ACK_HINT + " {} - or document it in annotations.yaml."
    box = [{"kind": "instant", "title": "Homelab-Drift: pi", "message": "Container x is new." + hint.format("D-0003"),
            "findings": ["D-0003"], "created": "2026-11-04T23:00:00+01:00", "tries": 0},
           {"kind": "instant", "title": "Homelab-Drift: pi", "message": "Port 18999/tcp is new." + hint.format("D-0004"),
            "findings": ["D-0004"], "created": "2026-11-04T23:00:01+01:00", "tries": 0},
           {"kind": "instant", "title": "Homelab-Drift: sff", "message": "Host sff unreachable: x", "findings": ["D-0005"],
            "created": "2026-11-04T23:00:02+01:00", "tries": 0}]
    out = _bundle(box)
    assert len(out) == 2 and out[0]["findings"] == ["D-0003", "D-0004"]
    assert out[0]["message"].startswith("Container x is new.\nPort 18999/tcp is new.")
    assert out[0]["message"].count("Acknowledge") == 1 and "ack D-0003 D-0004" in out[0]["message"]
    assert out[1]["title"] == "Homelab-Drift: sff"


@needs_git
def test_service_pages_of_removed_items_disappear(cfg, outputs):
    ha = FakeHA()
    run(cfg, outputs, ha)
    assert list(cfg.www_dir.glob("service-pi-docker-uptime-kuma-old-v1.html"))
    d = json.loads(outputs["pi"]["docker"])
    d["containers"] = [c for c in d["containers"] if c["Name"] != "/uptime-kuma-old-v1"]
    outputs["pi"]["docker"] = json.dumps(d)
    run(cfg, outputs, ha)
    assert not list(cfg.www_dir.glob("service-pi-docker-uptime-kuma-old-v1.html"))


@needs_git
def test_unreachable_host_keeps_last_docs_and_alerts(cfg, outputs):
    ha = FakeHA()
    run(cfg, outputs, ha)
    down = {"pi": {v: Unreachable("ssh: connect to host 127.0.0.1 port 22: Connection refused") for v in outputs["pi"]}}
    s = run(cfg, down, ha, 2)
    assert s.confirmed[0]["kind"] == "health" and "unreachable" in ha.sent[-1][1]
    host = (cfg.www_dir / "host-pi.html").read_text(encoding="utf-8")
    assert "Unreachable during the last scan" in host and "homeassistant" in host  # last known state stays visible
    assert ha.sensor[0] == "error"
    metrics = (cfg.www_dir / "metrics").read_text(encoding="utf-8")
    assert 'homelab_drift_host_reachable{host="pi"} 0' in metrics and "homelab_drift_scan_ok 0" in metrics


@needs_git
def test_gate_rejection_and_unavailable(cfg, outputs):
    ha = FakeHA()
    outputs["pi"]["tailscale"] = Result(3, "", "unavailable: tailscale not installed")
    outputs["pi"]["cron"] = Result(64, "", "homelab-drift-gate: command not allowed")
    s = run(cfg, outputs, ha, 2)
    assert any("gate rejected the verb" in p for p in s.health_problems)
    assert not any("tailscale" in p for p in s.health_problems)


@needs_git
def test_tool_vanishing_shows_collector_down_in_metrics(cfg, outputs):
    ha = FakeHA()
    run(cfg, outputs, ha)
    outputs["pi"]["nginx"] = Result(3, "", "unavailable: nginx not installed")
    s = run(cfg, outputs, ha, 2)
    assert s.confirmed[0]["title"] == "Collector nginx on pi returns nothing"
    m = (cfg.www_dir / "metrics").read_text(encoding="utf-8")
    assert 'homelab_drift_collector_up{host="pi",collector="nginx"} 0' in m


@needs_git
def test_ha_down_keeps_outbox_until_delivered(cfg, outputs):
    run(cfg, outputs, FakeHA())
    outputs["pi"]["ports"] = raw("ports") + PORT
    run(cfg, outputs, FakeHA(fail=True), 3)
    st = scan.State.load(cfg.data_dir)
    assert len(st.outbox) == 1 and st.outbox[0]["tries"] == 1
    ha = FakeHA()
    run(cfg, outputs, ha)
    assert len(ha.sent) == 1 and not scan.State.load(cfg.data_dir).outbox
    m = (cfg.www_dir / "metrics").read_text(encoding="utf-8")
    assert "homelab_drift_notify_failures_total 1" in m


@needs_git
def test_broken_annotations_alert_and_keep_last_good(cfg, outputs, tmp_path):
    ann = tmp_path / "annotations.yaml"
    ann.write_text('pi:\n  ports:\n    tcp/8091: "Wiki"\n', encoding="utf-8")
    ha = FakeHA()
    run(cfg, outputs, ha)
    ann.write_text("pi: [broken\n", encoding="utf-8")
    run(cfg, outputs, ha)
    assert ha.sent[-1][0] == "Homelab-Drift" and ha.sent[-1][1].startswith("annotations.yaml is invalid:")
    assert "Wiki" in (cfg.www_dir / "ports.html").read_text(encoding="utf-8")  # last good version stays in effect


@needs_git
def test_markdown_has_no_volatile_values(cfg, outputs):
    run(cfg, outputs, FakeHA())
    md = "\n".join(p.read_text(encoding="utf-8") for p in (cfg.repo_dir / "docs").rglob("*.md"))
    assert "Scanned" not in md and "started_at" not in md and "uptime_s" not in md and "use_percent" not in md


@needs_git
def test_multi_host(tmp_path, outputs):
    p = write_cfg(tmp_path, hosts=[{"name": "pi", "address": "127.0.0.1"},
                                    {"name": "sff", "address": "192.0.2.50", "collectors": ["system", "ports", "cron"]}])
    cfg = config.load(p)
    outputs["sff"] = {"system": raw("system").replace("pi-host", "sff"), "ports": raw("ports"), "cron": raw("cron")}
    ha = FakeHA()
    scan.run_scan(cfg, run=fake_runner(outputs), ha=ha)
    assert (cfg.www_dir / "host-sff.html").exists()
    ports_html = (cfg.www_dir / "ports.html").read_text(encoding="utf-8")
    assert 'host-sff.html#ports' in ports_html and 'host-pi.html#ports' in ports_html
    assert ha.sensor[1]["hosts"] == 2 and ha.sensor[1]["hosts_reachable"] == 2

    # sff goes down (open finding) and is then removed from the configuration -> everything closed
    outputs["sff"] = {v: Unreachable("gone") for v in ("system", "ports", "cron")}
    scan.run_scan(cfg, run=fake_runner(outputs), ha=ha)
    scan.run_scan(cfg, run=fake_runner(outputs), ha=ha)
    st = scan.State.load(cfg.data_dir)
    assert any(f["host"] == "sff" and f["status"] == "open" for f in st.findings)
    cfg2 = config.load(write_cfg(tmp_path))  # pi only
    scan.run_scan(cfg2, run=fake_runner(outputs), ha=ha)
    st = scan.State.load(cfg2.data_dir)
    assert "sff" not in st.baseline and not [f for f in st.findings if f["host"] == "sff" and f["status"] != "closed"]
    assert not (cfg2.www_dir / "host-sff.html").exists() and ha.sensor[0] == "ok"
    assert "Host sff removed from the configuration" in (cfg2.www_dir / "changelog.html").read_text(encoding="utf-8")


@needs_git
def test_maintenance_window_skips_scan_without_alerts(tmp_path, outputs):
    cfg = config.load(write_cfg(tmp_path, general__pause_while_active=["backup.service"]))
    ha = FakeHA()
    scan.run_scan(cfg, run=fake_runner(outputs), ha=ha, maintenance=lambda c: None)
    down = {"pi": {v: Unreachable("down for backup") for v in outputs["pi"]}}
    for _ in range(4):  # host "down" during the backup -> would alert, but the window pauses the scans
        s = scan.run_scan(cfg, run=fake_runner(down), ha=ha, maintenance=lambda c: "backup.service")
        assert s.paused == "backup.service"
    st = scan.State.load(cfg.data_dir)
    assert not st.findings and not st.outbox and st.meta["last_pause"]["unit"] == "backup.service"
    s = scan.run_scan(cfg, run=fake_runner(outputs), ha=ha, maintenance=lambda c: None)
    assert not s.paused and not s.health_problems and not ha.sent
