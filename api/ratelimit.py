"""Shared rate-limit key: the real client IP.

The API only receives traffic via Caddy, which overwrites X-Forwarded-For with
the true peer address (see deploy/caddy/Caddyfile). Keying slowapi on the raw
socket peer would make every visitor share Caddy's container IP — one abusive
client would 429 the whole public dashboard.
"""
from slowapi.util import get_remote_address


def client_ip(request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return get_remote_address(request)
