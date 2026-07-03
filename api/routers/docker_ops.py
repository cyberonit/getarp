"""Docker management endpoints: service list, logs, versions, restart.

Intentionally read-only apart from restarts: the docker-socket-proxy this API
talks to (see docker-compose.yml) denies every other write, so image pulls,
rollbacks, container creation and exec are impossible even if this container
is compromised. Image updates are a host-side operation — see
maintenance/check-updates.sh and `make up`.
"""
import asyncio
import os

from fastapi import APIRouter, Depends, HTTPException, Query

import audit
from auth import require_admin

router = APIRouter(prefix="/api/admin/docker", tags=["docker"])

ALLOWED_SERVICES = {
    "api", "frontend", "caddy", "pipeline", "enrichment", "analytics",
    "postgres", "redis", "cowrie", "extra-services", "suricata",
    "crowdsec", "docker-proxy",
}


def _validate_service(service: str):
    if service not in ALLOWED_SERVICES:
        raise HTTPException(400, f"unknown service: {service!r}")


def _client():
    import docker
    return docker.from_env()


def _compose_project():
    """Detect compose project name from our own container's labels."""
    import docker
    client = docker.from_env()
    hostname = os.environ.get("HOSTNAME", "")
    if hostname:
        try:
            me = client.containers.get(hostname)
            return me.labels.get("com.docker.compose.project", "")
        except Exception:
            pass
    containers = client.containers.list(
        filters={"label": "com.docker.compose.service=api"})
    for c in containers:
        proj = c.labels.get("com.docker.compose.project")
        if proj:
            return proj
    return ""


# ─────────────────────── list services ───────────────────────

@router.get("/services")
async def list_services(user=Depends(require_admin)):
    def _list():
        client = _client()
        project = _compose_project()
        filt = {"label": "com.docker.compose.project"} if not project else {
            "label": f"com.docker.compose.project={project}"}
        containers = client.containers.list(all=True, filters=filt)
        out = []
        for c in containers:
            labels = c.labels
            img = c.image
            image_tags = img.tags if img.tags else []
            out.append({
                "name": labels.get("com.docker.compose.service", c.name),
                "container_id": c.short_id,
                "status": c.status,
                "image": image_tags[0] if image_tags else img.short_id,
                "image_id": img.short_id,
                "created": c.attrs.get("Created", ""),
                "is_built": "com.docker.compose.image" not in labels
                            and bool(labels.get("com.docker.compose.service")),
            })
        out.sort(key=lambda s: s["name"])
        return out
    return await asyncio.to_thread(_list)


# ─────────────────────── service logs ────────────────────────

@router.get("/logs/{service}")
async def service_logs(
    service: str,
    lines: int = Query(150, ge=10, le=2000),
    user=Depends(require_admin),
):
    _validate_service(service)
    def _logs():
        client = _client()
        project = _compose_project()
        filt = {"label": [
            f"com.docker.compose.service={service}",
        ]}
        if project:
            filt["label"].append(f"com.docker.compose.project={project}")
        containers = client.containers.list(all=True, filters=filt)
        if not containers:
            return None
        c = containers[0]
        raw = c.logs(tail=lines, timestamps=True)
        return raw.decode("utf-8", errors="replace")
    result = await asyncio.to_thread(_logs)
    if result is None:
        raise HTTPException(404, f"service {service!r} not found")
    return {"service": service, "lines": lines, "log": result}


# ────────────────────── version info ─────────────────────────

@router.get("/versions")
async def service_versions(user=Depends(require_admin)):
    def _versions():
        client = _client()
        project = _compose_project()
        filt = {"label": "com.docker.compose.project"} if not project else {
            "label": f"com.docker.compose.project={project}"}
        containers = client.containers.list(all=True, filters=filt)
        out = []
        for c in containers:
            labels = c.labels
            svc = labels.get("com.docker.compose.service", c.name)
            img = c.image
            image_tags = img.tags if img.tags else []
            image_name = image_tags[0] if image_tags else img.short_id
            digest = img.attrs.get("RepoDigests", [""])[0]
            created_str = img.attrs.get("Created", "")
            out.append({
                "service": svc,
                "container_id": c.short_id,
                "status": c.status,
                "image": image_name,
                "image_id": img.id,
                "image_short_id": img.short_id,
                "digest": digest,
                "image_created": created_str,
            })
        out.sort(key=lambda s: s["service"])
        return out
    return await asyncio.to_thread(_versions)


# ───────────────────── restart service ───────────────────────

@router.post("/restart/{service}")
async def restart_service(service: str, user=Depends(require_admin)):
    _validate_service(service)
    def _restart():
        client = _client()
        project = _compose_project()
        filt = {"label": [f"com.docker.compose.service={service}"]}
        if project:
            filt["label"].append(f"com.docker.compose.project={project}")
        containers = client.containers.list(all=True, filters=filt)
        if not containers:
            return None
        c = containers[0]
        c.restart(timeout=30)
        c.reload()
        return {"service": service, "status": c.status, "note": "Service restarted."}

    result = await asyncio.to_thread(_restart)
    if result is None:
        raise HTTPException(404, f"service {service!r} not found")
    await audit.log(user["username"], "docker_restart", result)
    return result
