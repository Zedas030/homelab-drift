"""Docker containers from `docker inspect`: image, version, ports, volumes, networks, restart policy."""
from __future__ import annotations

import json

from . import Collector, Ctx, ParseError


def _short(image_id: str) -> str:
    return image_id.split(":", 1)[-1][:12] if image_id else ""


class DockerCollector(Collector):
    name = "docker"
    verb = "docker"
    label = "Container"
    # container ID, PIDs, start/creation time and health are deliberately NOT compared: they change without a real change
    compare = ("image", "image_id", "restart_policy", "network_mode", "networks", "ports", "mounts", "privileged", "running")
    volatile = ("health", "started_at", "state")

    def parse(self, raw: str, ctx: Ctx) -> list[dict]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ParseError(f"docker inspect returned no JSON: {e}") from e
        images = {i.get("Id"): i for i in data.get("images") or []}
        items = []
        for c in data.get("containers") or []:
            name = (c.get("Name") or "").lstrip("/")
            if not name or ctx.ignored("containers", name):
                continue
            cfg = c.get("Config") or {}
            hc = c.get("HostConfig") or {}
            st = c.get("State") or {}
            labels = cfg.get("Labels") or {}
            img = images.get(c.get("Image")) or {}
            img_labels = (img.get("Config") or {}).get("Labels") or {}
            rp = hc.get("RestartPolicy") or {}
            policy = rp.get("Name") or "no"
            if policy == "on-failure" and rp.get("MaximumRetryCount"):
                policy += f":{rp['MaximumRetryCount']}"
            ports = []
            for cport, binds in sorted((hc.get("PortBindings") or {}).items()):
                for b in binds or []:
                    ports.append(f"{b.get('HostIp') or '0.0.0.0'}:{b.get('HostPort')}->{cport}")
            mounts = []
            for m in c.get("Mounts") or []:
                src = m.get("Name") if m.get("Type") == "volume" else m.get("Source")
                mounts.append(f"{src}:{m.get('Destination')}{'' if m.get('RW', True) else ':ro'}")
            version = (labels.get("org.opencontainers.image.version") or img_labels.get("org.opencontainers.image.version") or "")
            digests = img.get("RepoDigests") or []
            items.append({
                "id": name,
                "image": cfg.get("Image", ""),
                "image_id": _short(c.get("Image", "")),
                "version": version,
                "repo_digest": digests[0].split("@", 1)[-1][:19] if digests else "",
                "image_created": (img.get("Created") or "")[:19],
                "state": st.get("Status", ""),
                "running": bool(st.get("Running")),
                "health": (st.get("Health") or {}).get("Status", ""),
                "started_at": (st.get("StartedAt") or "")[:19],
                "restart_policy": policy,
                "network_mode": hc.get("NetworkMode", ""),
                "networks": sorted(n for n in ((c.get("NetworkSettings") or {}).get("Networks", {}) or {}) if n != "_"),
                "ports": sorted(set(ports)),
                "mounts": sorted(mounts),
                "privileged": bool(hc.get("Privileged")),
                "compose_project": labels.get("com.docker.compose.project", ""),
                "compose_service": labels.get("com.docker.compose.service", ""),
            })
        return items

    def describe(self, item: dict) -> str:
        return f"Container {item['id']}"
