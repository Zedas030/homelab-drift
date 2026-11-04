"""Version the snapshots in a local git repository (one commit per scan with changes)."""
from __future__ import annotations

import subprocess
from pathlib import Path

from .util import log


class GitRepo:
    def __init__(self, path: Path):
        self.path = path

    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(self.path), *args], capture_output=True, text=True, check=check,
                              encoding="utf-8", errors="replace")

    def ensure(self) -> None:
        if (self.path / ".git").is_dir():
            return
        self.path.mkdir(parents=True, exist_ok=True)
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.name", "Homelab-Drift")
        self._git("config", "user.email", "homelab-drift@localhost")
        self._git("config", "commit.gpgsign", "false")
        (self.path / "README.md").write_text(
            "# Homelab-Drift snapshots\n\nGenerated automatically. `snapshots/<host>/<collector>.json` holds the state per scan,\n"
            "`docs/` the generated Markdown documentation, `CHANGELOG.md` the change log.\n"
            "History of one source: `git log -p -- snapshots/<host>/ports.json`\n", encoding="utf-8")

    def commit_all(self, message: str) -> str | None:
        """Commit everything if something changed. Returns the commit hash or None."""
        self._git("add", "-A")
        if self._git("diff", "--cached", "--quiet", check=False).returncode == 0:
            return None
        r = self._git("commit", "-q", "-m", message, check=False)
        if r.returncode != 0:
            log.error("git commit failed: %s", r.stderr.strip())
            raise RuntimeError(f"git commit failed: {r.stderr.strip()}")
        return self._git("rev-parse", "--short", "HEAD").stdout.strip()

    def log(self, n: int = 30) -> list[dict]:
        if not (self.path / ".git").is_dir():
            return []
        r = self._git("log", f"-{n}", "--format=%h%x1f%cI%x1f%s", check=False)
        out = []
        for line in r.stdout.splitlines():
            parts = line.split("\x1f")
            if len(parts) == 3:
                out.append({"hash": parts[0], "date": parts[1], "subject": parts[2]})
        return out
