# Maintenance Scripts

## check-updates.sh

Checks all project dependencies for outdated versions and applies updates in three stages.

### Usage

```bash
bash maintenance/check-updates.sh check    # (default) dry-run — report only, no changes
bash maintenance/check-updates.sh apply    # update requirements pins + npm packages, pull base images
bash maintenance/check-updates.sh commit   # make build, make rules, then git commit + push the pins
```

(`--apply` is still accepted as an alias for the apply stage.)

### What each stage covers

| Stage | Step | Tool | Touches |
|---|---|---|---|
| check | report outdated Python/npm/base-image versions | `pip`, `npm`, docker | nothing |
| apply | re-pin Python packages | `pip` | `api/requirements.txt`, `pipeline/requirements.txt` |
| apply | update npm packages | `npm` (via Docker) | `frontend/package.json` |
| apply | pull latest base images | `docker compose pull` | local image cache |
| commit | rebuild images | `make build` | local images |
| commit | refresh + reload Suricata ET Open rules | `make rules` equivalent | `ids/suricata/rules/suricata.rules` |
| commit | commit + push dependency changes | `git` | only the files the apply stage edits |

### Workflow

1. `check` — review what's outdated.
2. Check any flagged `requirements.txt` pins before upgrading — some are pinned for compatibility reasons (e.g. `bcrypt==4.0.1` due to passlib 1.7.4 incompatibility with newer versions).
3. `apply` — update the pins and npm packages, pull new base images.
4. `commit` — rebuild the images, refresh the Suricata rules, and commit + push the dependency bumps (only `requirements.txt` / `package.json` files; unrelated working-tree changes are left alone).
5. Recreate containers to deploy the rebuilt images: `make up`

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
bash maintenance/check-updates.sh apply
bash maintenance/check-updates.sh commit
make up   # recreate containers on the rebuilt images
```
