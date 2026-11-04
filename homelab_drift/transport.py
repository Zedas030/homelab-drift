"""Connection to the hosts: key-based SSH to the gate (verbs only, no arguments)."""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Callable, Protocol

from .config import Config, Host

VERB_RE = re.compile(r"^[a-z]{2,16}$")


@dataclass
class Result:
    rc: int
    out: str
    err: str

    @property
    def unavailable(self) -> bool:
        return self.rc == 3


class Unreachable(Exception):
    """Host does not answer or refuses the login."""


class Runner(Protocol):
    def __call__(self, host: Host, verb: str) -> Result: ...


def ssh_runner(cfg: Config) -> Runner:
    def run(host: Host, verb: str) -> Result:
        if not VERB_RE.match(verb):
            raise ValueError(f"invalid verb {verb!r}")
        cmd = [
            "ssh", "-T",
            "-i", str(cfg.ssh_key),
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", f"UserKnownHostsFile={cfg.ssh_known_hosts}",
            # first contact: remember the host key (TOFU); afterwards it must not change
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ConnectTimeout={cfg.ssh_connect_timeout}",
            "-o", "ServerAliveInterval=10",
            "-o", "ServerAliveCountMax=3",
            "-o", "LogLevel=ERROR",
            # one SSH connection per host and scan instead of one per verb
            "-o", "ControlMaster=auto",
            "-o", f"ControlPath={cfg.ssh_key.parent / 'cm-%C'}",
            "-o", "ControlPersist=30",
            "-p", str(host.port),
            f"{host.user or cfg.ssh_user}@{host.address}",
            verb,
        ]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=cfg.ssh_command_timeout,
                               encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired as e:
            raise Unreachable(f"timeout after {cfg.ssh_command_timeout}s on '{verb}'") from e
        if p.returncode == 255:
            raise Unreachable((p.stderr or "ssh error").strip().splitlines()[-1])
        return Result(p.returncode, p.stdout, p.stderr.strip())
    return run


def fake_runner(outputs: dict[str, dict[str, Result | str | Exception]]) -> Runner:
    """For tests: outputs[host][verb] -> Result, text (rc 0) or exception."""
    def run(host: Host, verb: str) -> Result:
        v = outputs.get(host.name, {}).get(verb)
        if v is None:
            return Result(3, "", f"unavailable: {verb}")
        if isinstance(v, Exception):
            raise v
        if isinstance(v, str):
            return Result(0, v, "")
        return v
    return run


RunnerFactory = Callable[[Config], Runner]
