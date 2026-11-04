"""Command line: homelab-drift <command>. On the controller run it with sudo (the wrapper switches to the service user)."""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .config import ConfigError, load


def _setup_logging(verbose: bool) -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    root.addHandler(h)
    logdir = Path(os.environ.get("HOMELAB_DRIFT_LOG_DIR", "/var/log/homelab-drift"))
    if logdir.is_dir() and os.access(logdir, os.W_OK):
        fh = logging.FileHandler(logdir / "homelab-drift.log", encoding="utf-8")  # rotated by logrotate
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        root.addHandler(fh)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="homelab-drift",
                                 description="Homelab documentation generated from the real system state, with drift alerts.")
    ap.add_argument("-c", "--config", help="path to config.yaml (default /etc/homelab-drift/config.yaml)")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--version", action="version", version=f"homelab-drift {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="scan all hosts, detect drift, generate the docs")
    p.add_argument("--no-notify", action="store_true", help="do not send notifications (they stay in the outbox)")
    p.add_argument("--host", action="append", help="only this host (repeatable)")
    p = sub.add_parser("list", help="show open findings")
    p.add_argument("--all", action="store_true", help="include acknowledged and closed findings")
    p = sub.add_parser("ack", help="acknowledge finding(s): no further alerts")
    p.add_argument("ids", nargs="*", help="IDs such as D-0007 or 7")
    p.add_argument("--item", help="all open findings of one item, e.g. pi/ports/tcp/8091")
    p.add_argument("--reason", default="", help="reason (shown in the docs and the changelog)")
    p.add_argument("--until", help="informational expiry date YYYY-MM-DD (for real expiry use annotations.yaml)")
    p = sub.add_parser("unack", help="withdraw an acknowledgement")
    p.add_argument("ids", nargs="*")
    p.add_argument("--item")
    p = sub.add_parser("digest", help="send the daily digest now")
    p.add_argument("--dry-run", action="store_true", help="only show it, send nothing")
    sub.add_parser("status", help="short status; exit code 0 ok, 1 open findings, 2 problems")
    sub.add_parser("check", help="check config, annotations, SSH/gate on every host and Home Assistant")
    sub.add_parser("render", help="regenerate the docs (no scan)")
    sub.add_parser("test-notify", help="send a test notification through Home Assistant")
    p = sub.add_parser("notify-failure", help="(internal, systemd OnFailure) report a failed run")
    p.add_argument("unit")
    p = sub.add_parser("import-docs", help="import notes from an existing HTML documentation page into a new annotations.yaml")
    p.add_argument("html", help="e.g. /var/www/wiki/index.html")
    p.add_argument("--host", default="pi", help="host name from config.yaml the notes belong to")
    p.add_argument("--output", help="target file (only created, never overwritten); without it: print to stdout")
    args = ap.parse_args(argv)

    if args.cmd == "import-docs":
        return _import_docs(args)
    try:
        cfg = load(args.config)
    except ConfigError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 2
    _setup_logging(args.verbose)

    from . import scan
    try:
        if args.cmd == "scan":
            s = scan.run_scan(cfg, notify=not args.no_notify, only_hosts=args.host)
            if s.paused:
                print(f"Scan skipped: maintenance unit {s.paused} is active.")
                return 0
            print(f"Scan finished: {s.changes} confirmed change(s), {s.pending} pending, "
                  f"{len(s.health_problems)} problem(s).")
            for f in s.confirmed:
                print(f"  [{f['id']}] {f['host']}: {f['title']} ({f['severity']}, {f['status']})")
            for p_ in s.health_problems:
                print(f"  Problem: {p_}")
            return 0
        if args.cmd == "list":
            return _list(cfg, args.all)
        if args.cmd in ("ack", "unack"):
            if not args.ids and not args.item:
                print("Give IDs or --item (IDs: homelab-drift list)", file=sys.stderr)
                return 2
            for line in scan.change_acks(cfg, args.ids, reason=getattr(args, "reason", ""), until=getattr(args, "until", None),
                                         undo=args.cmd == "unack", item=args.item,
                                         by=f"cli ({os.environ.get('SUDO_USER') or os.environ.get('USER') or 'unknown'})"):
                print(line)
            return 0
        if args.cmd == "digest":
            msg = scan.run_digest(cfg, dry_run=args.dry_run)
            if not msg:
                print("Nothing to report - no digest sent.")
            else:
                print(("(preview only) " if args.dry_run else "Sent: ") + msg[0] + "\n" + msg[1])
            return 0
        if args.cmd == "status":
            return _status(cfg)
        if args.cmd == "check":
            return _check(cfg)
        if args.cmd == "render":
            from .util import file_lock
            with file_lock(cfg.state_dir / ".lock"):
                c = scan.open_context(cfg)
                scan.publish(c, notify=False)
                c.state.save()
            print(f"Docs regenerated in {cfg.www_dir}")
            return 0
        if args.cmd == "test-notify":
            from .notify import HomeAssistant
            HomeAssistant(cfg).notify("Homelab-Drift: test", "Test notification - the connection to Home Assistant works.",
                                      url=cfg.base_url)
            print(f"Test notification sent via {cfg.notify_service}.")
            return 0
        if args.cmd == "notify-failure":
            from .notify import HomeAssistant
            HomeAssistant(cfg).notify("Homelab-Drift: run failed",
                                      f"{args.unit} exited with an error. Details: journalctl -u {args.unit} -n 50",
                                      tag="homelab-drift-failure")
            return 0
    except Exception as e:  # make it visible; exit code != 0 -> systemd OnFailure reports as well
        logging.getLogger("homelab_drift").exception("Error in '%s': %s", args.cmd, e)
        return 1
    return 0


def _list(cfg, show_all: bool) -> int:
    from .store import State
    st = State.load(cfg.data_dir)
    rows = st.findings if show_all else st.open_findings()
    if not rows:
        print("No open findings." if not show_all else "No findings stored.")
        return 0
    for f in sorted(rows, key=lambda x: x["id"]):
        ack = f" - {f['ack'].get('reason')}" if f.get("ack") and f["ack"].get("reason") else ""
        print(f"{f['id']}  {f['status']:<12} {f['severity']:<7} {f['host']:<10} {f['title']}{ack}")
    return 0


def _status(cfg) -> int:
    from .store import State
    st = State.load(cfg.data_dir)
    open_ = st.open_findings()
    problems = st.meta.get("last_health_problems", [])
    print(f"Last scan: {st.meta.get('last_scan', 'none yet')} · open findings: {len(open_)} · "
          f"pending: {len(st.pending)} · outbox: {len(st.outbox)}")
    for p in problems:
        print(f"Problem: {p}")
    return 2 if problems else 1 if open_ else 0


def _check(cfg) -> int:
    from . import annotations as ann
    from .collectors import registry
    from .notify import HAError, HomeAssistant
    from .transport import Unreachable, ssh_runner
    ok = True
    print(f"Configuration {cfg.path}: ok ({len(cfg.hosts)} host(s))")
    try:
        notes = ann.load(cfg.annotations_file, [h.name for h in cfg.hosts], list(registry()))
        print(f"Annotations {cfg.annotations_file}: ok" + "".join(f"\n  Note: {w}" for w in notes.warnings))
    except ann.AnnotationsError as e:
        ok = False
        print(f"Annotations: ERROR {e}")
    if not cfg.ssh_key.exists():
        ok = False
        print(f"SSH key {cfg.ssh_key}: missing")
    run = ssh_runner(cfg)
    for h in cfg.hosts:
        if h.type == "fritzbox":
            print(f"Host {h.name} (FRITZ!Box): " + ("credentials present" if cfg.fritz_user and cfg.fritz_password
                                                   else "FRITZ_USER/FRITZ_PASSWORD missing in .env"))
            continue
        try:
            r = run(h, "ping")
            print(f"Host {h.name} ({h.address}): {'ok, ' + r.out.strip() if r.rc == 0 else 'gate error ' + r.err}")
            ok &= r.rc == 0
            # self-test: the gate must reject anything not on its list
            bad = run(h, "reboot")
            if bad.rc == 0:
                ok = False
                print(f"  WARNING: the gate on {h.name} did not reject 'reboot'!")
            else:
                print(f"  Gate rejects unlisted commands: ok (rc {bad.rc})")
        except Unreachable as e:
            ok = False
            print(f"Host {h.name} ({h.address}): UNREACHABLE - {e}")
    try:
        HomeAssistant(cfg).ping()
        print(f"Home Assistant {cfg.ha_url}: ok (token valid, notifications via {cfg.notify_service})")
    except HAError as e:
        ok = False
        print(f"Home Assistant: ERROR {e}")
    return 0 if ok else 2


def _import_docs(args) -> int:
    from .importdocs import extract, to_yaml
    html = Path(args.html).read_text(encoding="utf-8-sig", errors="replace")
    data = extract(html, args.host)
    text = to_yaml(data, args.html)
    n = sum(len(v) for v in data.get(args.host, {}).values())
    if not args.output:
        print(text)
        return 0
    out = Path(args.output)
    if out.exists():
        print(f"{out} already exists - it is never overwritten. Preview without --output.", file=sys.stderr)
        return 2
    out.write_text(text, encoding="utf-8")
    print(f"{n} notes imported into {out}.")
    return 0
