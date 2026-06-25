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
| Deception | Cowrie (SSH) + multi-service emulator (HTTP, fake MySQL, FTP, Redis) | `honeypot/` |
| Detection | Suricata IDS + custom honeypot rules | `ids/` |
| Intel + enforcement | CrowdSec + nftables firewall bouncer (host service) | `crowdsec/` |
| Ingest | Pipeline: normalize → Redis Streams + TimescaleDB | `pipeline/` |
| Enrichment | Swappable provider (CrowdSec CTI / AbuseIPDB / GreyNoise) | `enrichment/` |
| Analytics | Pluggable scan/attack detectors, behavioral profiler, 5-min status, daily reports | `analytics/` |
| Backend | FastAPI: JWT auth, settings, live WebSocket, report CSV export | `api/` |
| Frontend | React "deception-grid" dashboard | `frontend/` |
| Edge | Caddy auto-TLS (TLS-ALPN-01 on 443) | `deploy/caddy/` |

## Prerequisites

- **OS:** Ubuntu 22.04 or 24.04 (tested)
- **Hardware:** 8 vCPU / 64 GB RAM recommended (TimescaleDB is the hungry one)
- **DNS:** Point your domain's A record at the VM's public IP *before* running setup — Caddy issues TLS via TLS-ALPN-01 on port 443
- **Cloud firewall / security group** — open inbound before running setup:

| Port(s) | Purpose |
|---|---|
| 22 | Honeypot SSH (Cowrie) |
| 80, 8081 | Honeypot HTTP |
| 21 | Honeypot FTP |
| 3306 | Honeypot fake MySQL |
| 6379 | Honeypot fake Redis |
| 443 | Dashboard TLS + ACME |

## Installation

```bash
git clone git@github.com:cyberonit/getarp.git getarp-intel
cd getarp-intel
sudo bash deploy/setup.sh
```

`setup.sh` is fully interactive — **do not edit `.env` manually first**. It will:

1. Ask for your domain, public NIC, management SSH port, DB credentials, admin credentials, and optional CTI API keys.
2. Auto-generate a `JWT_SECRET` and write `.env` (mode 600).
3. Move `sshd` off port 22 (Cowrie needs it) — **you will be prompted to confirm SSH still works before it continues**.
4. Install Docker (if not present).
5. Configure UFW with a default-deny policy, opening only the ports listed above.
6. Install `crowdsec-firewall-bouncer-nftables` as a host systemd service (no Docker image exists for it).
7. Pull images, build custom containers, and bring the stack up.
8. Register the firewall bouncer with the CrowdSec LAPI.
9. Pull Suricata ET Open rules and restart the IDS.

When it finishes you'll see:

```
  Dashboard  : https://<your-domain>
  Admin login: <admin-user>  (password as entered)
  SSH (admin): ssh -p <port> <user>@<vm-ip>
```

## Post-install (optional)

Enroll in the CrowdSec community console to share signals and pull the community blocklist:

```bash
make enroll T=<console-token>     # token from https://app.crowdsec.net
```

## Swapping the intelligence provider

The enrichment provider is set during `setup.sh` based on which API key you supply.
To change it at runtime via the admin Settings tab, or by editing `.env`:

```bash
ENRICHMENT_PROVIDER=multi          # recommended: queries all providers in parallel
VIRUSTOTAL_KEY=<your-key>
docker compose up -d enrichment    # recreate to pick up .env changes
```

| Provider | API key required | Notes |
|---|---|---|
| `crowdsec` | Optional (CTI key) | Default; falls back to local LAPI decisions without key |
| `abuseipdb` | Yes | Free tier: 1 000 checks/day |
| `greynoise` | Optional | Community API works without key, limited results |
| `virustotal` | Yes | Free tier: 500 lookups/day |
| `abusech` | No | Abuse.ch Feodo Tracker botnet C2 blocklist; no key needed |
| `multi` | — | Queries **all** providers in parallel and merges results (recommended) |

**Multi-provider merge logic:** most severe reputation wins (malicious > suspicious > unknown > clean), highest confidence wins, `is_known_attacker` is true if any provider flags the IP, geo/ASN uses the first non-null value, categories are the union of all providers. Each provider's raw response is stored separately for forensics.

Add a custom provider by subclassing `EnrichmentProvider` in `enrichment/providers.py`
and decorating it with `@register` — nothing else changes.

## Reports

Daily reports are generated automatically at 06:00 UTC and available in the **Reports**
tab. Each report exports as a single CSV containing an executive summary (total events,
unique IPs, scans, attacks by type) followed by the top 20 attackers table.

To regenerate the HTML for all existing reports after a template change, call the
admin endpoint:

```bash
curl -X POST https://<domain>/api/admin/reports/regenerate-html \
  -H "Authorization: Bearer <token>"
```

## Extending analytics

- **New detector:** subclass `Detector` in `analytics/correlation/`, `@register` it, add its key to `ENABLED_DETECTORS` in `.env`. The engine feeds it a per-IP sliding window.
- **AI scorer:** `analytics/behavioral/profiler.py` exposes `score(profile)`; drop in a model there, or run a separate container that consumes the `events` Redis stream and writes `attack_events.ai_score`.

## Day-to-day operations

```bash
make ps           # service health
make logs         # tail all logs
make rules        # refresh Suricata ET Open rules
make bouncer      # re-register firewall bouncer with CrowdSec LAPI
make psql         # open a psql shell into the database
make up           # rebuild + start the stack
make down         # stop the stack
make clean        # DANGER: stop + delete all volumes (destroys data)
```

## Not production yet — known gaps

This is a working PoC scaffold. Before production: HA Postgres + backups, a real secrets
manager (not `.env`), mTLS between internal services, signed/audited admin actions,
SOAR/ticketing integration, Suricata load-testing at line rate, and a formal
data-retention + lawful-basis review (captured payloads can contain third-party PII).
Each is noted in `docs/HIGH_LEVEL_DESIGN.md` §11.
