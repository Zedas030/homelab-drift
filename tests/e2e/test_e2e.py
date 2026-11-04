"""End-to-end test: real SSH test host (Docker), real gate, real scans; only Home Assistant is simulated.

Runs on a Linux machine with Docker:   pytest -m e2e tests/e2e
Covers: initial inventory, new open port -> instant alert after N scans, new root cron job -> instant alert,
acknowledgement, disappearance -> digest, git commits, docs, host outage -> alert and all-clear, and that the gate
allows nothing else over SSH.
"""
from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = [pytest.mark.e2e,
              pytest.mark.skipif(shutil.which("docker") is None or shutil.which("ssh") is None, reason="docker/ssh missing")]

from conftest import FakeHA, write_cfg  # noqa: E402
from homelab_drift import config, scan  # noqa: E402
from homelab_drift.transport import ssh_runner  # noqa: E402

NAME = "drift-e2e-host"
PORT = 2299


def sh(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=check)


@pytest.fixture(scope="module")
def testhost(tmp_path_factory):
    d = tmp_path_factory.mktemp("e2e")
    key = d / ".ssh" / "id_ed25519"
    key.parent.mkdir(mode=0o700)
    sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
    sh(str(ROOT / "scripts" / "testhost.sh"), "start", f"{key}.pub", str(PORT), NAME)
    yield d, key
    sh(str(ROOT / "scripts" / "testhost.sh"), "stop", NAME, check=False)


def make_cfg(d: Path, key: Path):
    p = write_cfg(d, hosts=[{"name": "testhost", "address": "127.0.0.1", "port": PORT,
                             "collectors": ["system", "ports", "nginx", "cron", "storage", "docker", "systemd", "tailscale"]}],
                  ssh={"user": "drift", "key": str(key), "known_hosts": str(key.parent / "known_hosts"),
                       "connect_timeout": 5, "command_timeout": 30},
                  drift__confirm_after_scans=2, drift__unreachable_after_scans=2)
    return config.load(p)


def exec_in(*cmd: str) -> None:
    sh("docker", "exec", NAME, *cmd)


def _reachable(run, h) -> bool:
    try:
        run(h, "ping")
        return True
    except Exception:
        return False


def test_end_to_end(testhost):
    d, key = testhost
    cfg = make_cfg(d, key)
    ha = FakeHA()
    run = ssh_runner(cfg)
    h = cfg.hosts[0]
    ssh = ["ssh", "-i", str(key), "-o", "BatchMode=yes", "-o", f"UserKnownHostsFile={key.parent / 'known_hosts'}",
           "-p", str(PORT), "drift@127.0.0.1"]

    # gate over real SSH: listed verbs work, nothing else does
    assert run(h, "ping").out.startswith("ok gate=1")
    assert run(h, "reboot").rc != 0
    raw = subprocess.run([*ssh, "cat /etc/shadow"], capture_output=True, text=True)
    assert raw.returncode == 64 and "not allowed" in raw.stderr
    shell = subprocess.run(ssh, capture_output=True, text=True, input="id\n")
    assert shell.returncode == 64  # no interactive shell

    # 1. initial inventory
    s = scan.run_scan(cfg, ha=ha)
    assert not s.health_problems, s.health_problems
    assert set(s.first_inventory) >= {"testhost/system", "testhost/ports", "testhost/cron", "testhost/nginx"}
    page = (cfg.www_dir / "host-testhost.html").read_text(encoding="utf-8")
    assert "80/tcp" in page and "test cron job" in page and "sshd" in page
    assert "Not present on this host" in page  # no docker/systemd/tailscale inside the container

    # 2. new open port + new root cron job -> instant alerts after 2 scans, bundled into ONE push
    exec_in("sh", "-c", "nohup nc -lk 18999 >/dev/null 2>&1 &")
    exec_in("sh", "-c", "echo '*/5 * * * * root /usr/bin/true # new' > /etc/cron.d/new")
    time.sleep(1)
    assert not scan.run_scan(cfg, ha=ha).confirmed
    s = scan.run_scan(cfg, ha=ha)
    titles = sorted(f["title"] for f in s.confirmed)
    assert any(t.startswith("Port 18999/tcp is new") for t in titles), titles
    assert any("running as root" in t for t in titles), titles
    assert all(f["severity"] == "instant" for f in s.confirmed)
    assert len(ha.sent) == 1 and ha.sensor[0] == "drift"
    assert "18999" in ha.sent[0][1] and "running as root" in ha.sent[0][1]
    port_id = next(f["id"] for f in s.confirmed if "18999" in f["title"])

    # 3. acknowledge -> no further alert
    assert scan.change_acks(cfg, [port_id], reason="e2e", ha=ha)[0].startswith(f"{port_id}: acknowledged")
    scan.run_scan(cfg, ha=ha)
    assert len(ha.sent) == 1

    # 4. port disappears -> "removed" finding in the digest
    exec_in("pkill", "-f", "nc -lk 18999")
    time.sleep(1)
    scan.run_scan(cfg, ha=ha)
    s = scan.run_scan(cfg, ha=ha)
    assert any(f["kind"] == "removed" and "18999" in f["title"] for f in s.confirmed)
    title, msg = scan.run_digest(cfg, ha=ha)
    assert "Port 18999/tcp is gone" in msg and ha.sent[-1][0] == title

    # 5. changelog and git
    cl = (cfg.www_dir / "changelog.html").read_text(encoding="utf-8")
    assert "Port 18999/tcp is new" in cl and "Acknowledged: Port 18999" in cl and "Port 18999/tcp is gone" in cl
    log = sh("git", "-C", str(cfg.repo_dir), "log", "--format=%s").stdout
    assert "Initial inventory" in log and "Port 18999/tcp is new" in log

    # 6. host goes down -> alert after 2 scans, then all-clear
    sh("docker", "stop", "-t", "1", NAME)
    scan.run_scan(cfg, ha=ha)
    s = scan.run_scan(cfg, ha=ha)
    assert s.confirmed and s.confirmed[0]["kind"] == "health"
    assert "Host testhost unreachable" in ha.sent[-1][1] and ha.sensor[0] == "error"
    sh("docker", "start", NAME)
    for _ in range(30):
        if _reachable(run, h):
            break
        time.sleep(1)
    scan.run_scan(cfg, ha=ha)
    assert ha.sent[-1][0] == "Resolved: testhost"
