# getarp.net — Defence Intelligence PoC

An internet-exposed deception sensor that captures live attacker traffic, runs an
IDS over it, enriches every observed IP with swappable threat intelligence,
correlates scans vs. attacks, profiles attacker behaviour, and surfaces it all in a
public dashboard with an authenticated admin backend — on a single VM.

> **Read `docs/HIGH_LEVEL_DESIGN.md` first.** It explains the architecture and the
> one principle everything follows: *a honeypot is built to be compromised, so the
> sensor is isolated from your data and admin plane.*

## What's in the box

| Layer | Component | Where |
|---|---|---|
| Deception | Cowrie (SSH/Telnet) + multi-service emulator (HTTP, fake MySQL "DB", FTP, Redis) | `honeypot/` |
| Detection | Suricata IDS + custom honeypot rules | `ids/` |
| Intel + enforcement | CrowdSec + firewall bouncer (nftables) | `crowdsec/` |
| Ingest | Pipeline: normalize → Redis Streams + TimescaleDB | `pipeline/` |
| Enrichment | Swappable provider (CrowdSec / AbuseIPDB / GreyNoise) | `enrichment/` |
| Analytics | Pluggable scan/attack detectors, behavioral profiler, 5-min status, reports | `analytics/` |
| Backend | FastAPI: JWT auth, settings, data, live WebSocket | `api/` |
| Frontend | React "deception-grid" dashboard | `frontend/` |
| Edge | Caddy auto-TLS for getarp.net | `deploy/caddy/` |

## Quick start (fresh Ubuntu 22.04/24.04 VM, 8 vCPU / 64 GB)

```bash
git clone <this repo> getarp-intel && cd getarp-intel
cp .env.example .env          # then edit: passwords, JWT_SECRET, ADMIN_PASSWORD
sudo bash deploy/setup.sh
```

`bootstrap.sh` will, in order:
1. **Move your real sshd off port 22** (Cowrie needs it) → reconnect on `MGMT_PORT`.
2. Install Docker, set a default-deny host firewall exposing only the honeypot ports + 443 + your mgmt port.
3. Detect the public NIC and write it into `.env`.
4. Build and launch the stack.

Then pull IDS rules and (optionally) join the CrowdSec community blocklist:

```bash
make rules
make enroll T=<console-token>     # from https://app.crowdsec.net
```

Dashboard: `https://getarp.net` · admin login uses `ADMIN_USER`/`ADMIN_PASSWORD` from `.env`.

## DNS / cloud prerequisites

- Point `getarp.net` (and `www`) A records at the VM's public IP so Caddy can issue a cert.
- Cloud security group must allow inbound: `22, 23, 80, 21, 3306, 6379, 8081` (honeypot),
  `443` (dashboard), and your `MGMT_PORT` (admin SSH). Mirror the host firewall.
- Port 80 is taken by the honeypot, so Caddy issues the TLS cert via **TLS-ALPN-01 on 443** —
  no action needed, just don't expect an HTTP→HTTPS redirect.

## Swapping the intelligence provider

```bash
# .env
ENRICHMENT_PROVIDER=abuseipdb      # crowdsec | abuseipdb | greynoise
ABUSEIPDB_KEY=...
docker compose restart enrichment
```
Add a new provider by subclassing `EnrichmentProvider` in `enrichment/providers.py`
and decorating it with `@register` — nothing else changes.

## Adding a correlation / behavioral / AI module

- **New detector:** subclass `Detector` in `analytics/correlation/`, `@register` it, add
  its key to `ENABLED_DETECTORS`. The engine feeds it a per-IP sliding window.
- **AI scorer:** `analytics/behavioral/profiler.py` exposes `score(profile)`; drop in a
  model there, or run a separate container that consumes the `events` Redis stream and
  writes `attack_events.ai_score`. The canonical schema + persisted `raw` transcripts mean
  no migration is required.

## Operating

```bash
make ps        # service health
make logs      # tail everything
make psql      # inspect the database
make clean     # tear down + delete data
```

## Not production yet — known gaps

This is a working PoC scaffold. Before production: HA Postgres + backups, a real secrets
manager (not `.env`), mTLS between internal services, signed/audited admin actions,
SOAR/ticketing integration, Suricata load-testing at line rate, and a formal
data-retention + lawful-basis review (captured payloads can contain third-party PII).
Each is noted in `docs/HIGH_LEVEL_DESIGN.md` §11.
