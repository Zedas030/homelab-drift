"""Configuration, annotations, documentation import, metrics format, gate allow-list."""
import datetime as dt
import re
import shutil
import subprocess

import pytest
import yaml

from conftest import ROOT, write_cfg
from homelab_drift import annotations as ann
from homelab_drift import config
from homelab_drift.importdocs import extract, to_yaml


# ------------------------------------------------------------------ configuration
def test_example_config_loads(cfg):
    assert cfg.confirm_after_scans == 3 and cfg.notify_service == "notify.mobile_app_phone"
    assert cfg.ha_token == "test-token" and cfg.hosts[0].collectors[0] == "system"


@pytest.mark.parametrize("over,msg", [
    ({"hosts": []}, "at least one host"),
    ({"hosts": [{"name": "a"}]}, "required"),
    ({"hosts": [{"name": "a", "address": "x"}, {"name": "a", "address": "y"}]}, "duplicate"),
    ({"hosts": [{"name": "a", "address": "x", "collectors": ["nonsense"]}]}, "unknown collectors"),
    ({"hosts": [{"name": "a b", "address": "x"}]}, "invalid name"),
    ({"drift__confirm_after_scans": 0}, ">= 1"),
    ({"notify__digest_time": "25:00"}, "HH:MM"),
    ({"ui__home_url": "javascript:alert(1)"}, "ui.home_url"),
])
def test_config_validation(tmp_path, over, msg):
    with pytest.raises(config.ConfigError, match=msg):
        config.load(write_cfg(tmp_path, **over))


def test_ui_home_link(tmp_path, cfg):
    assert cfg.home_url == "" and cfg.home_label == "Dashboard"  # example config: no button
    c = config.load(write_cfg(tmp_path, ui={"home_url": "http://dashboard.example.local/", "home_label": "House"}))
    assert c.home_url == "http://dashboard.example.local/" and c.home_label == "House"


def test_secrets_from_env_file_and_environment(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text('# comment\nexport HA_TOKEN="abc"\nFRITZ_USER=drift\nFRITZ_PASSWORD=\'p w\'\n', encoding="utf-8")
    c = config.load(write_cfg(tmp_path))
    assert (c.ha_token, c.fritz_user, c.fritz_password) == ("abc", "drift", "p w")
    monkeypatch.setenv("HA_TOKEN", "from-env")
    assert config.load(write_cfg(tmp_path)).ha_token == "from-env"


def test_missing_config():
    with pytest.raises(config.ConfigError, match="not found"):
        config.load("/does/not/exist.yaml")


# ------------------------------------------------------------------ annotations
def test_annotations_merge_and_patterns(tmp_path):
    p = tmp_path / "a.yaml"
    p.write_text("""
all:
  ports:
    "udp/eph/*": {note: ephemeral, known: true}
    tcp/22: SSH
pi:
  _host: My Pi
  ports:
    tcp/22: {note: "SSH (key only)", known: true, until: 2099-01-01, reason: ok}
  nonsense: {}
stranger: {}
""", encoding="utf-8")
    a = ann.load(p, ["pi"], ["ports", "docker"])
    assert a.host_note("pi") == "My Pi"
    n = a.get("pi", "ports", "tcp/22")
    assert n.note == "SSH (key only)" and n.acknowledged() and n.until == dt.date(2099, 1, 1)
    assert a.get("other", "ports", "tcp/22").note == "SSH" and not a.get("other", "ports", "tcp/22").acknowledged()
    assert a.get("pi", "ports", "udp/eph/avahi").acknowledged()
    assert not a.get("pi", "ports", "tcp/80").documented
    assert any("stranger" in w for w in a.warnings) and any("nonsense" in w for w in a.warnings)


def test_annotations_errors(tmp_path):
    p = tmp_path / "a.yaml"
    p.write_text("pi: [broken", encoding="utf-8")
    with pytest.raises(ann.AnnotationsError):
        ann.load(p, ["pi"], ["ports"])
    assert ann.load(tmp_path / "missing.yaml", ["pi"], ["ports"]).warnings


# ------------------------------------------------------------------ documentation import
DOC = """<html><body><h2>Ports</h2><p>x</p>
<table><tr><th>Port</th><th>Proto</th><th>Service</th><th>Exposure</th></tr>
<tr><td>53</td><td>tcp/udp</td><td>Pi-hole DNS</td><td>LAN</td></tr>
<tr><td>8091</td><td>tcp</td><td>nginx &middot; <b>Wiki</b></td><td>LAN + Tailscale</td></tr>
</table>
<h2>Docker</h2><table><tr><th>Container</th><th>Image</th><th>Status</th><th>Network</th><th>Ports</th><th>Data</th></tr>
<tr><td>homeassistant</td><td>ha:stable</td><td>Up</td><td>host</td><td>8123</td><td>~/homeassistant</td></tr></table>
<h2>Maintenance</h2><table><tr><th>Task</th><th>When</th></tr><tr><td>1</td><td>daily</td></tr></table>
</body></html>"""


def test_import_docs():
    d = extract(DOC, "pi")
    assert d["pi"]["ports"]["tcp/53"] == "Pi-hole DNS (exposure: LAN)" and "udp/53" in d["pi"]["ports"]
    assert d["pi"]["ports"]["tcp/8091"] == "nginx · Wiki (exposure: LAN + Tailscale)"
    assert "data: ~/homeassistant" in d["pi"]["docker"]["homeassistant"]
    assert d["all"]["ports"]["udp/eph/*"]["known"] is True
    text = to_yaml(d, "/var/www/wiki/index.html")
    assert text.startswith("# Homelab-Drift") and yaml.safe_load(text)["pi"]["ports"]["tcp/53"]


def test_import_docs_accepts_german_headers():
    de = DOC.replace("<th>Service</th><th>Exposure</th>", "<th>Dienst</th><th>Erreichbar</th>")
    assert extract(de, "pi")["pi"]["ports"]["tcp/53"] == "Pi-hole DNS (exposure: LAN)"


def test_import_docs_cli_never_overwrites(tmp_path):
    from homelab_drift.cli import main
    src = tmp_path / "docs.html"
    src.write_text(DOC, encoding="utf-8")
    out = tmp_path / "annotations.yaml"
    assert main(["import-docs", str(src), "--output", str(out)]) == 0
    first = out.read_text(encoding="utf-8")
    assert main(["import-docs", str(src), "--output", str(out)]) == 2
    assert out.read_text(encoding="utf-8") == first


# ------------------------------------------------------------------ gate
GATE = ROOT / "gate" / "drift-gate"
SSH = ROOT / "gate" / "drift-ssh"
bash = shutil.which("bash")


def gate_verbs() -> set[str]:
    text = GATE.read_text(encoding="utf-8")
    body = text.split('case "$VERB" in', 1)[1]
    return set(re.findall(r"^  ([a-z]+)\)", body, re.M))


def test_gate_verbs_match_sudoers_and_collectors():
    from homelab_drift.collectors import registry
    sudo = re.search(r'^VERBS="([^"]+)"', (ROOT / "scripts" / "install-host.sh").read_text(encoding="utf-8"), re.M).group(1)
    assert set(sudo.split()) == gate_verbs()
    needed = {c.verb for c in registry().values() if c.verb}
    assert needed | {"ping"} == gate_verbs()


def test_gate_has_no_mutating_commands():
    text = GATE.read_text(encoding="utf-8")
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    for bad in (r"\brm\b", r"\bmv\b", r"\bkill", r"\breboot\b", r"\bdocker (run|rm|stop|start|exec|pull)",
                r"systemctl (start|stop|restart|enable|disable|reload)", r">\s*/(?!dev/null)", r"\beval\b",
                r"\bsh -c\b", r"\btee\b"):
        assert not re.search(bad, code), bad


@pytest.mark.skipif(bash is None, reason="bash not available")
@pytest.mark.parametrize("args", [["reboot"], ["ping", "extra"], ["docker; id"], ["../ping"], [""]])
def test_gate_rejects(args):
    r = subprocess.run([bash, str(GATE), *args], capture_output=True, text=True)
    assert r.returncode == 64, (args, r.stdout, r.stderr)
    assert "not allowed" in r.stderr


@pytest.mark.skipif(bash is None, reason="bash not available")
@pytest.mark.parametrize("cmd", ["ping; id", "ls -la", "PING", "ping\nid", "$(id)", "a" * 20])
def test_ssh_wrapper_rejects(cmd):
    r = subprocess.run([bash, str(SSH)], capture_output=True, text=True, env={"SSH_ORIGINAL_COMMAND": cmd, "PATH": "/usr/bin:/bin"})
    assert r.returncode == 64, cmd


@pytest.mark.skipif(bash is None, reason="bash not available")
def test_gate_ping_works():
    r = subprocess.run([bash, str(GATE), "ping"], capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.startswith("ok gate=1")


# ------------------------------------------------------------------ metrics format
def test_metrics_format(cfg):
    from homelab_drift import metrics
    from homelab_drift.store import State
    st = State.load(cfg.data_dir)
    st.meta.update(last_scan="2026-11-04T22:00:00+01:00", scans=3)
    st.findings = [{"severity": "instant", "status": "open"}, {"severity": "digest", "status": "acknowledged"}]
    text = metrics.render(cfg, st, {"duration": 1.234, "ok": True,
                                    "hosts": {"pi": {"reachable": True, "collectors": {"ports": {"status": "ok", "items": 41},
                                                                                     "tailscale": {"status": "unavailable", "items": 0}}}}})
    line_re = re.compile(r'^(# (HELP|TYPE) .+|[a-z_]+(\{[a-z_]+="[^"]*"(,[a-z_]+="[^"]*")*\})? -?[0-9.e+]+)$')
    for line in text.strip().splitlines():
        assert line_re.match(line), line
    assert 'homelab_drift_collector_items{host="pi",collector="ports"} 41' in text
    assert "tailscale" not in text  # tools that are not installed are not an outage
    assert 'homelab_drift_findings{severity="instant",status="open"} 1' in text


def test_unquoted_until_date_survives_json_cache():
    # YAML reads an unquoted 2026-12-31 as a date; the notes cache (JSON) must not crash on it
    from homelab_drift.util import dumps, short_hash
    data = yaml.safe_load('pi:\n  docker:\n    old:\n      known: true\n      until: 2026-12-31\n')
    assert isinstance(data["pi"]["docker"]["old"]["until"], dt.date)
    assert '"until": "2026-12-31"' in dumps(data)
    assert short_hash(data)
