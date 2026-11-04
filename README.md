# Homelab-Drift

**Documentation of your homelab, generated from the real system state - and an alert when reality drifts away from it.**

Hand-written homelab docs go stale the day after you write them. Homelab-Drift scans your hosts every 15 minutes
(read-only, over SSH), versions every state as JSON in a local git repository, renders documentation pages from it and
tells you when something changes that nobody documented:

> **Homelab-Drift: pi** - Port 18999/tcp is new (exposed: all, process docker-proxy) - not documented anywhere.
> Is this expected? Acknowledge with: `homelab-drift ack D-0004`

Built for a Raspberry Pi running Home Assistant (Docker), Grafana and Prometheus, but it monitors any Linux host
reachable over SSH.

## Contents

- [What it does](#what-it-does)
- [What gets reported, and when](#what-gets-reported-and-when)
- [Security: read-only by design](#security-read-only-by-design)
- [Installation](#installation)
- [Secrets](#secrets)
- [Daily use](#daily-use)
- [Your annotations](#your-annotations)
- [Adding hosts](#adding-hosts)
- [Self-monitoring](#self-monitoring)
- [Notifications, sensor, metrics](#notifications-sensor-metrics)
- [Configuration reference](#configuration-reference)
- [Update and uninstall](#update-and-uninstall)
- [Development](#development)

## What it does

| | |
|---|---|
| **Collects** | Docker containers (image, version, ports, volumes, networks, restart policy), listening ports with process and exposure, nginx sites and upstreams, cron jobs (all users and `/etc/cron.*`), systemd services and timers, mounts and disk space, Tailscale status, optionally the device list of an AVM FRITZ!Box (TR-064) |
| **Versions** | every scan as `snapshots/<host>/<collector>.json` in a local git repository - `git log -p` shows when what changed |
| **Documents** | a static site (overview, one page per host, one per container/unit/nginx site, port overview, changelog) plus the same content as Markdown in the repository |
| **Merges your notes** | from `annotations.yaml` into every page - never overwritten by a regeneration |
| **Detects drift** | against the last confirmed baseline, with a noise filter |
| **Alerts** | through a Home Assistant notify service: instantly for undocumented, security-relevant changes, everything else in a daily digest |
| **Watches itself** | a broken collector, an unreachable host, a crashed scan or a scan that stopped running altogether all end in an alert instead of silence |

Each collector is a small module (`homelab_drift/collectors/`). On the monitored host a fixed shell script, the
**gate**, produces the raw output; the controller parses it. A full scan of a Raspberry Pi takes about 7 seconds and
30 MB of memory.

<details>
<summary>Screens</summary>

The generated site has a light and a dark theme and works on a phone: overview with open findings and hosts, a page per
host (containers, ports, nginx, cron, systemd, storage, Tailscale), a page per service with its history, a port
overview across all hosts that maps every port to its container or nginx site, and the changelog.
</details>

## What gets reported, and when

| Event | Alert |
|---|---|
| New port reachable from the network (LAN or all interfaces), not documented | **instant** |
| New cron job or systemd timer running as root, not documented | **instant** |
| New container with a published port, `--privileged` or host networking, not documented | **instant** |
| Host unreachable, collector failed or suddenly returns nothing, invalid annotations file, crashed scan | **instant** (plus an all-clear once it recovers) |
| Everything else: container gone or stopped, image updated, service failed, mount full, kernel update, reboot, new tailnet device, … | daily digest (19:00) |

**Noise filter.** A difference only counts once it persists for `confirm_after_scans` scans in a row (default 3 =
45 minutes). If it disappears earlier or changes again, counting starts over - short restarts and flapping states never
reach you. Container IDs, PIDs, uptimes and disk usage in percent never count; ephemeral ports are grouped per process
(`udp/eph/avahi-daemon`); on-demand services (D-Bus/one-shot) only count when they fail. If an item returns to its
original state before you acknowledged the change, both cancel out: no alert, just a changelog entry.

Several instant findings of one host from one scan arrive as **one** push notification.

## Security: read-only by design

Read-only is enforced on every monitored host, including the controller itself:

- User **`drift`** without a password and without an interactive login.
- Its SSH key is restricted in `authorized_keys`: `command=".../drift-ssh"` (forced command), `no-pty`, no forwarding,
  optionally `from=`.
- **`drift-ssh`** only accepts a single lower-case word and hands it to the gate via sudo.
- **`/etc/sudoers.d/homelab-drift`** allows exactly `drift-gate ping|system|docker|ports|nginx|cron|systemd|storage|tailscale` -
  no arguments.
- **`drift-gate`** runs fixed, read-only commands per verb: `docker inspect` with a field selection (so container
  environment variables - often passwords - never leave the host), `ss -tulpnH`, reading nginx and cron files,
  `systemctl show`, `findmnt`, `tailscale status --json`. Anything else is rejected with exit code 64 and logged via
  `logger` (tag `homelab-drift-gate`).
- `drift` is deliberately **not** in the docker group (that would be root-equivalent).

On the controller the service runs as user `homelab-drift` in a hardened systemd unit (`ProtectSystem=strict`, no
capabilities, writes only to its own directories; `systemd-analyze security` rates it 3.0 "OK").
`sudo homelab-drift check` verifies on every host that the gate rejects a forbidden command.

## Installation

Requirements on the controller: Debian / Raspberry Pi OS, Python ≥ 3.11, git, nginx, Home Assistant with the REST API.

```bash
git clone https://github.com/Zedas030/homelab-drift.git && cd homelab-drift
sudo ./scripts/install.sh --nginx --prometheus     # optional: --import-docs /var/www/wiki/index.html
sudo nano /etc/homelab-drift/.env                  # HA_TOKEN, see "Secrets"
sudo nano /etc/homelab-drift/config.yaml           # notify service, base URL, hosts
sudo ./scripts/install.sh --ha-setup               # dead man's switch automation in Home Assistant
sudo homelab-drift check
sudo systemctl start homelab-drift.service         # first scan = initial inventory (no alerts)
```

`install.sh` creates:
- the service user `homelab-drift`, the program in `/opt/homelab-drift` with its own venv and the wrapper
  `/usr/local/bin/homelab-drift`,
- the service's SSH key and the gate on the controller itself (key valid from 127.0.0.1 only),
- the systemd units and timers (enabled, so they start after a reboot) and logrotate,
- optionally the nginx site on port 8097 and a Prometheus scrape job (with backup and `promtool check config`).

It is idempotent - running it again updates. An existing `config.yaml`, `.env` or `annotations.yaml` is never
overwritten.

**Why systemd and not Docker Compose?** The tool only needs outgoing SSH. A container would not isolate it better than
the hardened unit does, and "scan every 15 minutes" is a timer, not a daemon - between scans Homelab-Drift uses no
memory at all. `Persistent=true` catches up on runs missed during a reboot.

**Resources:** `CPUQuota=50%`, `MemoryMax=256M`, `Nice=10`, `IOSchedulingClass=idle`, `TimeoutStartSec=10min`.

## Secrets

All secrets live in **`/etc/homelab-drift/.env`** (owner `homelab-drift`, `chmod 600`) - never in `config.yaml`, the
code or the git repository. Template: [`config/env.example`](config/env.example).

| Variable | Used for | Where to get it |
|---|---|---|
| `HA_TOKEN` | notifications and the status sensor | Home Assistant → Profile → Security → Long-lived access tokens → *Create token* (name it e.g. `homelab-drift`) |
| `FRITZ_USER`, `FRITZ_PASSWORD` | only for a host with `type: fritzbox` | FRITZ!Box → System → FRITZ!Box Users: a dedicated user with the "FRITZ!Box settings" permission |

**Set or change:** `sudo nano /etc/homelab-drift/.env`. No restart needed - the next scan reads the file again. Then run
`sudo homelab-drift check` and `sudo homelab-drift test-notify`.

**Rotate:** create the new token in Home Assistant, put it into `.env`, verify with `sudo homelab-drift check`, and only
then delete the old token. The same for the FRITZ!Box password.

**The service's SSH key** (`/var/lib/homelab-drift/.ssh/id_ed25519`): to rotate, delete it
(`sudo rm /var/lib/homelab-drift/.ssh/id_ed25519*`) and run `sudo ./scripts/install.sh` - it creates a new key and
registers it locally. Then run `install-host.sh` with the new public key on every other host.

## Daily use

```bash
sudo homelab-drift list                         # open findings with IDs
sudo homelab-drift ack D-0007 --reason "test service, stays"
sudo homelab-drift ack --item pi/ports/tcp/8091 # all open findings of one item
sudo homelab-drift unack D-0007
sudo homelab-drift scan                         # scan now (otherwise every 15 min)
sudo homelab-drift digest --dry-run             # preview the daily digest
sudo homelab-drift status                       # exit code 0 ok, 1 open findings, 2 problems
sudo homelab-drift check                        # config, SSH + gate self-test on every host, Home Assistant
sudo homelab-drift test-notify
```

`sudo` is required because the command switches to the service user, so the state files keep the right owner.

There are two ways to acknowledge:
1. `homelab-drift ack <ID>` - for exactly this finding. If the same item changes again later, you get a new alert.
2. `known: true` in `annotations.yaml` - permanently for the item (optionally `until: YYYY-MM-DD`).

## Your annotations

`/etc/homelab-drift/annotations.yaml` belongs to you (editable without sudo by the user who installed). The tool never
writes to it.

```yaml
pi:                                   # host name from config.yaml, or "all"
  _host: "Raspberry Pi in the hallway"
  ports:
    tcp/8091: "nginx · wiki"                                # makes the port "documented"
    tcp/18999: {note: "test service", known: true, until: 2026-12-31, reason: "until the end of the year"}
  docker:
    homeassistant: "Home Assistant, config in ~/homeassistant"
  systemd:
    smartmontools.service: {note: "SD card has no SMART", known: true}
all:
  ports:
    "udp/eph/*": {note: "ephemeral ports", known: true}     # * and ? patterns are allowed
```

Items are named as in the docs (port `tcp/8091`, container name, unit name, mount path, nginx site `file:port`, cron
ID); every service page shows its key. Notes appear on every page and influence the classification: a documented item
only ever goes into the digest. If the file becomes invalid YAML, the last valid version stays in effect and you get an
instant alert.

**Seeding from an existing wiki page:** `homelab-drift import-docs page.html --output annotations.yaml` imports HTML
tables with the columns *Port / Proto / Service (/ Exposure)* and *Container / … / Network / Data*.

## Adding hosts

1. Copy the repository to the new host and run there:
   ```bash
   sudo ./scripts/install-host.sh "$(ssh <controller> cat /var/lib/homelab-drift/.ssh/id_ed25519.pub)" --from <controller-ip>
   ```
2. On the controller, add it to `/etc/homelab-drift/config.yaml`:
   ```yaml
     - name: server
       address: 192.0.2.50
       description: "Small form factor server"
   ```
3. `sudo homelab-drift check`. The first scan of the new host is its initial inventory and reports nothing.

Collectors whose tool is missing on a host (no Docker, no systemd, no Tailscale) are shown as "not present" - that is
not an error. Removing a host from the configuration closes its open findings automatically.

**FRITZ!Box device list:** add a host with `type: fritzbox` and `address: <router IP>`, put the credentials into `.env`.

## Self-monitoring

| Failure | Who notices |
|---|---|
| Collector fails or suddenly returns 0 items | Homelab-Drift (instant alert after 2 scans, all-clear on recovery). An empty result never wipes the baseline - only once you acknowledge the alert does "empty" become the new truth |
| Host unreachable | Homelab-Drift (after `unreachable_after_scans`, default 2) |
| Scan crashes | systemd `OnFailure=` → `homelab-drift-failed@…` sends a notification |
| No scan for a long time (host off, timer stuck) | the next scan: "Homelab-Drift did not scan for X" |
| Scans stop entirely | **Home Assistant automation** "Homelab-Drift: dead man's switch": `sensor.homelab_drift` older than 75 min |
| Home Assistant unreachable | notifications stay in an outbox and are delivered with the next scan (up to 48 h); metric `homelab_drift_outbox_messages` |
| Git versioning fails | instant alert; the scan itself continues |

**Maintenance windows.** A full-system backup that stops Docker on purpose should not wake you up. List such units in
`general.pause_while_active` (e.g. `["raspiBackup.service"]`): while one of them is active on the controller, scans are
skipped - no alerts, and the skipped scans do not count as "not scanning".

## Notifications, sensor, metrics

- **Notifications** go to the notify service in `config.yaml` (e.g. `notify.mobile_app_phone`) and open the docs
  when tapped.
- **Sensor** `sensor.homelab_drift`: state `ok` / `drift` / `error`, attributes `last_scan`, `open_findings`,
  `open_instant`, `pending`, `hosts_reachable`, `findings` (top 10), `url`.
- **Prometheus** at `http://<controller>:8097/metrics`: `homelab_drift_last_scan_timestamp_seconds`,
  `homelab_drift_scan_ok`, `homelab_drift_collector_up{host,collector}`, `homelab_drift_collector_items`,
  `homelab_drift_host_reachable`, `homelab_drift_findings{severity,status}`, `homelab_drift_outbox_messages`,
  `homelab_drift_notify_failures_total`, …
- **Grafana:** import [`config/grafana-dashboard.json`](config/grafana-dashboard.json).

## Configuration reference

Everything lives in one commented YAML file, [`config/config.example.yaml`](config/config.example.yaml): hosts and
their collectors, scan interval, `confirm_after_scans`, storage thresholds, ignore lists (containers, units, ports,
mounts, cron jobs, tailnet peers), notify service, digest time, Home Assistant URL and sensor.
Scan interval and digest time are part of the systemd timers - apply changes with
`sudo /opt/homelab-drift/app/scripts/install.sh --schedule`.

| Path | Content |
|---|---|
| `/etc/homelab-drift/config.yaml` | configuration |
| `/etc/homelab-drift/annotations.yaml` | your notes |
| `/etc/homelab-drift/.env` | secrets (600) |
| `/var/lib/homelab-drift/repo/` | git repository with snapshots, Markdown docs, `CHANGELOG.md` |
| `/var/lib/homelab-drift/www/` | generated site (nginx, port 8097) and `/metrics` |
| `/var/lib/homelab-drift/state/` | baseline, findings, changelog, outbox |
| `/var/log/homelab-drift/` | log file (logrotate, 14 days); also `journalctl -u homelab-drift` |

## Update and uninstall

**Update:** pull the new version and run `sudo ./scripts/install.sh` again.

**Uninstall:** `sudo ./scripts/uninstall.sh` (keeps data and configuration) or `sudo ./scripts/uninstall.sh --purge`.
Remove the scrape job `homelab_drift` from `/etc/prometheus/prometheus.yml` and the Home Assistant automation by hand.
On other hosts: `sudo ./scripts/install-host.sh --remove`.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -e .[test]
.venv/bin/pytest                    # unit tests: parsers, drift engine, noise filter, acknowledgement, docs, metrics, gate
.venv/bin/pytest -m e2e tests/e2e   # end-to-end: real SSH test host in Docker, real gate, real scans
```

The fixtures in `tests/fixtures/` are anonymised outputs of a real Raspberry Pi. The end-to-end test builds a
throw-away container (sshd, cron, nginx) with `scripts/testhost.sh`, sets up the gate with the same `install-host.sh`
as a real host, runs the whole workflow (inventory → new port and root cron job → one bundled alert → acknowledgement →
disappearance → digest → changelog and git → host outage and all-clear) and cleans up afterwards.

```
homelab_drift/collectors/   one module per source (system, docker, ports, nginx, cron, systemd, storage, tailscale, fritzbox)
homelab_drift/engine.py     drift detection, noise filter, classification, acknowledgement, health, digest
homelab_drift/scan.py       one scan: collect -> store -> compare -> alert -> docs -> git
homelab_drift/render.py     HTML/Markdown from templates/
gate/                       drift-gate + drift-ssh (run on the monitored hosts)
scripts/                    install.sh (controller), install-host.sh (every host), uninstall.sh, ha_setup.py, testhost.sh
systemd/  config/           units, timers, example configuration, nginx, logrotate, HA automation, Grafana dashboard
```

## License

[MIT](LICENSE)
