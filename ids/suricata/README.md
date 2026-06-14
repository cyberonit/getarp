# Suricata IDS notes

`suricata.yaml` here is a lean, low-volume config sized for the PoC box. Two things
to know:

1. **Rules.** `rules/getarp-local.rules` ships with custom honeypot-aware rules
   (sids 9000001+). The big ET Open ruleset is NOT bundled — pull it after first boot:

   ```bash
   docker compose exec suricata suricata-update
   docker compose restart suricata
   ```
   This populates `rules/suricata.rules`, which `suricata.yaml` already references.

2. **Interface.** Suricata runs with `network_mode: host` and reads `PUBLIC_IFACE`
   from `.env` (auto-detected by `bootstrap.sh`). Confirm with `ip a` if traffic
   isn't showing up; a wrong interface is the #1 reason `eve.json` stays empty.

`eve.json` lands on the shared `honeypot_logs` volume and is consumed by both the
pipeline (for the dashboard) and CrowdSec (for enforcement) — independently, on
purpose, so a noisy rule can't blind the dashboard.

Tuning for higher traffic: raise `af-packet.threads`, switch `detect.profile` to
`medium`, and give the container more CPU in `docker-compose.yml`.
