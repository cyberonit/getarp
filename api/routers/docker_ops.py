"""Docker management endpoints: service logs, image updates, rollback."""
import asyncio
import json
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query

from auth import require_admin

router = APIRouter(prefix="/api/admin/docker", tags=["docker"])

SOCKET = "/var/run/docker.sock"


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


# ───────────────────── pull update ───────────────────────────

@router.post("/pull/{service}")
async def pull_update(service: str, user=Depends(require_admin)):
    """Pull the latest image for a service and recreate its container."""
    def _pull():
        client = _client()
        project = _compose_project()
        filt = {"label": [f"com.docker.compose.service={service}"]}
        if project:
            filt["label"].append(f"com.docker.compose.project={project}")
        containers = client.containers.list(all=True, filters=filt)
        if not containers:
            return None, "service not found"
        c = containers[0]
        old_img = c.image
        tags = old_img.tags
        if not tags:
            return None, "no image tag found — cannot pull (locally built image?)"

        image_ref = tags[0]
        old_id = old_img.id

        # save rollback info
        _save_rollback(client, service, old_id, image_ref)

        # pull latest
        repo, tag = image_ref.rsplit(":", 1) if ":" in image_ref else (image_ref, "latest")
        new_img = client.images.pull(repo, tag=tag)
        new_id = new_img.id

        return {
            "service": service,
            "old_image_id": old_id[:19],
            "new_image_id": new_id[:19],
            "changed": old_id != new_id,
            "image": image_ref,
            "note": "Image pulled. Restart the service to apply."
                    if old_id != new_id else "Already up to date.",
        }, None

    result, err = await asyncio.to_thread(_pull)
    if err:
        raise HTTPException(400, err)
    return result


# ───────────────────── rollback ──────────────────────────────

ROLLBACK_LABEL = "getarp.rollback"

def _save_rollback(client, service, image_id, image_ref):
    """Tag the current image so we can restore it later."""
    try:
        img = client.images.get(image_id)
        rollback_tag = f"getarp-rollback/{service}:previous"
        img.tag(rollback_tag)
    except Exception:
        pass


@router.post("/rollback/{service}")
async def rollback_service(service: str, user=Depends(require_admin)):
    """Restore the previous image for a service."""
    def _rollback():
        client = _client()
        rollback_tag = f"getarp-rollback/{service}:previous"
        try:
            img = client.images.get(rollback_tag)
        except Exception:
            return None, "no rollback image found for this service"

        project = _compose_project()
        filt = {"label": [f"com.docker.compose.service={service}"]}
        if project:
            filt["label"].append(f"com.docker.compose.project={project}")
        containers = client.containers.list(all=True, filters=filt)
        if not containers:
            return None, "service container not found"

        c = containers[0]
        current_img = c.image
        current_tags = current_img.tags or []

        if not current_tags:
            return None, "current container has no image tag — cannot rollback"

        original_tag = current_tags[0]
        img.tag(original_tag)

        return {
            "service": service,
            "restored_image_id": img.short_id,
            "tag": original_tag,
            "note": "Previous image restored. Restart the service to apply.",
        }, None

    result, err = await asyncio.to_thread(_rollback)
    if err:
        raise HTTPException(400, err)
    return result


# ───────────────────── restart service ───────────────────────

@router.post("/restart/{service}")
async def restart_service(service: str, user=Depends(require_admin)):
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
    return result
