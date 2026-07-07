"""Shared rate-limit key: the real client IP.

The API only receives legitimate traffic via Caddy, which overwrites
X-Forwarded-For with the true peer address (see deploy/caddy/Caddyfile). So the
leftmost XFF entry is the real client — but *only* when the request actually
came from Caddy.

X-Forwarded-For is a client-supplied header. If we honored it unconditionally, a
caller that can reach the API directly (a mis-exposed port, or a compromised
same-host container hitting api:8000) could rotate XFF to bypass the login
brute-force lockout and every per-IP rate limit. So we honor XFF only when the
direct TCP peer (not spoofable) is a trusted proxy listed in TRUSTED_PROXIES;
for any other peer we fall back to the socket peer address.

TRUSTED_PROXIES is a comma-separated CIDR list (the proxy network, e.g. the
frontend_net subnet Caddy connects from). If it is empty, no XFF is trusted and
every request keys on its socket peer — fail closed, never open.
"""
import ipaddress
import os

from slowapi.util import get_remote_address

_TRUSTED_PROXIES = [
    ipaddress.ip_network(c.strip())
    for c in os.environ.get("TRUSTED_PROXIES", "").split(",")
    if c.strip()
]


def _peer_is_trusted(peer: str) -> bool:
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(addr in net for net in _TRUSTED_PROXIES)


def client_ip(request) -> str:
    peer = get_remote_address(request)  # real TCP source; not spoofable
    if _peer_is_trusted(peer):
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            candidate = xff.split(",")[0].strip()
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                pass  # malformed XFF from the proxy — fall back to peer
    return peer
