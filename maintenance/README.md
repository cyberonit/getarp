# Maintenance Scripts

## check-updates.sh

Checks all project dependencies for outdated versions and optionally applies updates.

### Usage

```bash
# Dry-run — report only, no changes
bash maintenance/check-updates.sh

# Apply all updates
bash maintenance/check-updates.sh --apply
```

### What it covers

| Layer | Tool | Source |
|---|---|---|
| Python packages | `pip` | `api/requirements.txt`, `pipeline/requirements.txt` |
| Frontend npm packages | `npm` (via Docker) | `frontend/package.json` |
| Docker base images | `docker compose pull` | `docker-compose.yml` |
| Suricata IDS rules | `suricata-update` | ET Open ruleset |

### Workflow

1. Run the dry-run to review what's outdated.
2. Check any flagged `requirements.txt` pins before upgrading — some are pinned for compatibility reasons (e.g. `bcrypt==4.0.1` due to passlib 1.7.4 incompatibility with newer versions).
3. Run with `--apply` to update everything.
4. Rebuild containers: `make build`

> Suricata rules can also be updated independently with `make rules`.

## Scheduled runs

A crontab entry runs the dry-run automatically on the **1st of every month at 08:00**:

```
0 8 1 * * bash /home/getarp-intel/maintenance/check-updates.sh >> /home/getarp-intel/maintenance/logs/updates-$(date +%Y-%m).log 2>&1
```

Logs are written to `maintenance/logs/updates-YYYY-MM.log` (one file per month, excluded from git).

To review the latest log:

```bash
cat maintenance/logs/updates-$(date +%Y-%m).log
```

To apply updates after reviewing:

```bash
bash maintenance/check-updates.sh --apply
make build
```
