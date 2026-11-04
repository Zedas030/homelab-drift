import pytest

from conftest import raw
from homelab_drift.collectors import ParseError, registry

REG = registry()


def ids(items):
    return [i["id"] for i in items]


def test_system(ctx):
    [s] = REG["system"].parse(raw("system"), ctx)
    assert s["hostname"] == "pi-host" and s["kernel"].startswith("6.")
    assert s["boot_time"].startswith("2026-11-04") and s["cpus"] == 4
    with pytest.raises(ParseError):
        REG["system"].parse("garbage", ctx)


def test_docker_fields_and_no_secrets(ctx):
    items = REG["docker"].parse(raw("docker"), ctx)
    by = {i["id"]: i for i in items}
    assert len(items) == 9
    assert by["uptime-kuma"]["ports"] == ["0.0.0.0:3001->3001/tcp"]
    assert by["uptime-kuma"]["mounts"] == ["uptime-kuma-data:/app/data"]
    assert by["uni-meter"]["network_mode"] == "host"
    assert by["homeassistant"]["version"]  # version from the OCI label
    assert by["uptime-kuma-old-v1"]["running"] is False
    assert all("_" not in i["networks"] for i in items)
    assert "Env" not in raw("docker")  # the gate never outputs environment variables (passwords)


def test_docker_ignore_pattern(cfg, ctx):
    cfg.ignore["containers"] = ["fritz*"]
    names = ids(REG["docker"].parse(raw("docker"), ctx))
    assert not any(n.startswith("fritz") for n in names)


def test_ports_grouping_scope_and_ephemeral(ctx):
    items = REG["ports"].parse(raw("ports"), ctx)
    by = {i["id"]: i for i in items}
    assert by["tcp/8091"]["exposure"] == "all" and by["tcp/8091"]["processes"] == ["nginx"]
    assert by["tcp/631"]["exposure"] == "local"
    assert by["tcp/1400"]["exposure"] == "LAN"
    assert by["udp/546"]["exposure"] == "link-local"
    # IPv4 + IPv6 merged into one item
    assert len(by["tcp/8091"]["addresses"]) == 2
    # ephemeral ports per process, the port number is not part of the ID
    assert "udp/eph/avahi-daemon" in by and by["udp/eph/avahi-daemon"]["port"] is None
    assert by["tcp/eph/tailscaled"]["exposure"] == "Tailscale"
    # docker-proxy in the ephemeral range stays a fixed port
    extra = raw("ports") + 'tcp LISTEN 0 4096 0.0.0.0:40000 0.0.0.0:* users:(("docker-proxy",pid=1,fd=3))\n'
    assert "tcp/40000" in ids(REG["ports"].parse(extra, ctx))


def test_ports_requires_header(ctx):
    with pytest.raises(ParseError):
        REG["ports"].parse("tcp LISTEN 0 1 0.0.0.0:22 0.0.0.0:*", ctx)


def test_nginx_sites_and_upstreams(ctx):
    items = REG["nginx"].parse(raw("nginx"), ctx)
    by = {i["id"]: i for i in items}
    assert set(by) >= {"wiki:8091", "monitoring:8092", "restore-probe:8096"}
    assert by["wiki:8091"]["root"] == "/var/www/wiki"
    assert any("127.0.0.1:18095" in p for p in by["monitoring:8092"]["proxies"])
    text = """### FILE /etc/nginx/conf.d/app.conf
upstream backend { server 10.0.0.5:8080; server 10.0.0.6:8080 backup; }
server { listen 443 ssl; server_name app.example.local; # comment
  location / { proxy_pass http://backend; } }
"""
    by = {i["id"]: i for i in REG["nginx"].parse(text, ctx)}
    assert by["upstream:backend"]["servers"] == ["10.0.0.5:8080", "10.0.0.6:8080 backup"]
    assert by["app.conf:443"]["proxies"] == ["/ → http://backend"]
    assert by["app.conf:443"]["server_name"] == ["app.example.local"]


def test_cron_all_sources(ctx):
    items = REG["cron"].parse(raw("cron"), ctx)
    users = {i["user"] for i in items}
    assert {"root", "pihole"} <= users
    assert any(i["schedule"] == "@reboot" for i in items)
    assert any(i["command"] == "/etc/cron.daily/logrotate" and i["schedule"] == "@daily" for i in items)
    extra = raw("cron") + "### USER pi\nMAILTO=x\n*/5 * * * * /home/pi/bin/check.sh\n# comment\n"
    mine = [i for i in REG["cron"].parse(extra, ctx) if i["user"] == "pi"]
    assert len(mine) == 1 and mine[0]["source"] == "crontab:pi" and mine[0]["schedule"] == "*/5 * * * *"
    # same ID when only the schedule changes -> "changed" instead of "removed + added"
    a = REG["cron"].parse("### USER pi\n0 1 * * * /x\n", ctx)[0]
    b = REG["cron"].parse("### USER pi\n0 2 * * * /x\n", ctx)[0]
    assert a["id"] == b["id"]


def test_systemd_services_and_timers(ctx):
    items = REG["systemd"].parse(raw("systemd"), ctx)
    by = {i["id"]: i for i in items}
    assert by["nginx.service"]["state"] == "active" and by["nginx.service"]["user"] == "root"
    assert by["grafana-server.service"]["user"] == "grafana"
    assert by["smartmontools.service"]["state"] == "failed"
    assert by["smartmontools.service"]["run_state"] == "failed"
    # on-demand services: active vs. inactive makes no difference for drift
    assert by["bluetooth.service"]["run_state"] == "ready" and by["nginx.service"]["run_state"] == "active"
    txt = raw("systemd")
    i = txt.index("Id=bluetooth.service")
    flipped_txt = txt[:i] + txt[i:].replace("ActiveState=active\nSubState=running", "ActiveState=inactive\nSubState=dead", 1)
    flipped = {x["id"]: x for x in REG["systemd"].parse(flipped_txt, ctx)}
    assert flipped["bluetooth.service"]["state"] == "inactive"
    assert REG["systemd"].comparable(flipped["bluetooth.service"]) == REG["systemd"].comparable(by["bluetooth.service"])
    t = by["restic-backup.timer"]
    assert t["kind"] == "timer" and "next_elapse" not in t["schedule"] and t["schedule"].startswith("OnCalendar=")
    # one-shot services that only a timer starts are listed with the timer
    assert "restore-probe.service" not in by and "restore-probe.timer" in by
    # the ignore list from the example configuration applies
    assert not any(i.startswith("systemd-") for i in by)


def test_storage_levels(cfg, ctx):
    items = REG["storage"].parse(raw("storage"), ctx)
    assert ids(items) == ["/", "/boot/firmware", "/mnt/nas-share"]
    assert all(i["level"] == "ok" for i in items)
    cfg.storage_warn_percent, cfg.storage_crit_percent = 20, 30
    lv = {i["id"]: i["level"] for i in REG["storage"].parse(raw("storage"), ctx)}
    assert lv["/"] == "critical" and lv["/boot/firmware"] == "ok"


def test_tailscale_unique_ids(ctx):
    items = REG["tailscale"].parse(raw("tailscale"), ctx)
    assert ids(items)[0] == "self" and items[0]["backend_state"] == "Running"
    assert len(set(ids(items))) == len(items) == 4
    assert "phone" in ids(items) and "localhost" not in ids(items)


def test_fritzbox_hostlist(ctx):
    xml = """<?xml version="1.0"?><List>
<Item><Index>1</Index><IPAddress>192.0.2.20</IPAddress><MACAddress>AA:BB:CC:00:00:01</MACAddress><Active>1</Active>
<HostName>nas</HostName><InterfaceType>Ethernet</InterfaceType></Item>
<Item><Index>2</Index><IPAddress>192.0.2.21</IPAddress><MACAddress>AA:BB:CC:00:00:02</MACAddress><Active>0</Active>
<HostName>phone</HostName><InterfaceType>802.11</InterfaceType></Item></List>"""
    items = REG["fritzbox"].parse(xml, ctx)
    assert ids(items) == ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"]
    assert items[0]["active"] is True and items[1]["interface"] == "802.11"
    with pytest.raises(ParseError):
        REG["fritzbox"].parse("<broken", ctx)


def test_stable_strips_volatile(ctx):
    [s] = REG["system"].parse(raw("system"), ctx)
    assert "uptime_s" in s and "uptime_s" not in REG["system"].stable(s)
    for name, col in REG.items():
        assert set(col.compare).isdisjoint(col.volatile), name
