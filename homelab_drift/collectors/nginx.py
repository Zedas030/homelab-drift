"""nginx sites and upstreams from the configuration files (sites-enabled, conf.d)."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from . import Collector, Ctx

TOKEN_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]|[^\s{};"\']+')


@dataclass
class Node:
    name: str
    args: list[str]
    children: list["Node"] = field(default_factory=list)


def _strip_comments(text: str) -> str:
    out = []
    for line in text.splitlines():
        res, q = [], None
        for ch in line:
            if q:
                res.append(ch)
                if ch == q:
                    q = None
            elif ch in "\"'":
                q = ch
                res.append(ch)
            elif ch == "#":
                break
            else:
                res.append(ch)
        out.append("".join(res))
    return "\n".join(out)


def parse_tree(text: str) -> list[Node]:
    tokens = TOKEN_RE.findall(_strip_comments(text))
    root: list[Node] = []
    stack: list[list[Node]] = [root]
    cur: list[str] = []
    for t in tokens:
        if t == ";":
            if cur:
                stack[-1].append(Node(cur[0], cur[1:]))
            cur = []
        elif t == "{":
            node = Node(cur[0] if cur else "", cur[1:])
            stack[-1].append(node)
            stack.append(node.children)
            cur = []
        elif t == "}":
            if len(stack) > 1:
                stack.pop()
            cur = []
        else:
            cur.append(t.strip("\"'"))
    return root


def _walk(nodes: list[Node], name: str):
    for n in nodes:
        if n.name == name:
            yield n
        yield from _walk(n.children, name)


def split_files(raw: str) -> list[tuple[str, str]]:
    files, cur, buf = [], None, []
    for line in raw.splitlines():
        if line.startswith("### FILE "):
            if cur:
                files.append((cur, "\n".join(buf)))
            cur, buf = line[9:].strip(), []
        else:
            buf.append(line)
    if cur:
        files.append((cur, "\n".join(buf)))
    return files


class NginxCollector(Collector):
    name = "nginx"
    verb = "nginx"
    label = "nginx site"
    compare = ("listen", "server_name", "root", "proxies", "servers")

    def parse(self, raw: str, ctx: Ctx) -> list[dict]:
        items, seen = [], set()
        for path, text in split_files(raw):
            tree = parse_tree(text)
            base = os.path.basename(path)
            for srv in _walk(tree, "server"):
                if not srv.children:  # "server host:port;" in upstream
                    continue
                listen = sorted({" ".join(n.args) for n in srv.children if n.name == "listen"}) or ["80"]
                names = [a for n in srv.children if n.name == "server_name" for a in n.args]
                root = next((n.args[0] for n in srv.children if n.name == "root" and n.args), "")
                proxies = []
                for loc in _walk(srv.children, "location"):
                    for n in loc.children:
                        if n.name in ("proxy_pass", "fastcgi_pass", "uwsgi_pass", "grpc_pass") and n.args:
                            proxies.append(f"{' '.join(loc.args)} → {n.args[0]}")
                        elif n.name == "alias" and n.args:
                            proxies.append(f"{' '.join(loc.args)} → alias {n.args[0]}")
                for n in srv.children:
                    if n.name == "proxy_pass" and n.args:
                        proxies.append(f"/ → {n.args[0]}")
                ports = sorted({p for l in listen for p in re.findall(r"(?:^|:|\])(\d+)(?:\s|$)", l)}, key=int)
                sid = f"{base}:{ports[0] if ports else 'default'}"
                n = 2
                while sid in seen:
                    sid = f"{base}:{ports[0] if ports else 'default'}#{n}"
                    n += 1
                seen.add(sid)
                items.append({"id": sid, "kind": "server", "file": path, "listen": listen, "ports": [int(p) for p in ports],
                              "server_name": names, "root": root, "proxies": sorted(set(proxies)), "servers": []})
            for up in _walk(tree, "upstream"):
                if not up.args:
                    continue
                uid = f"upstream:{up.args[0]}"
                if uid in seen:
                    continue
                seen.add(uid)
                servers = sorted(" ".join(n.args) for n in up.children if n.name == "server")
                items.append({"id": uid, "kind": "upstream", "file": path, "listen": [], "ports": [], "server_name": [],
                              "root": "", "proxies": [], "servers": servers})
        return items

    def describe(self, item: dict) -> str:
        if item.get("kind") == "upstream":
            return f"nginx upstream {item['id'].split(':', 1)[1]}"
        return f"nginx site {item['id']}"
