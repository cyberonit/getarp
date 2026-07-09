# Maintenance Scripts

## check-updates.sh

Checks all project dependencies for outdated versions and applies updates in three stages.

### Usage

```bash
bash maintenance/check-updates.sh check    # (default) dry-run — report only, no changes
bash maintenance/check-updates.sh apply    # update requirements pins + npm packages, pull base images
bash maintenance/check-updates.sh commit   # make up, make rules, then git commit + push the pins
```

(`--apply` is still accepted as an alias for the apply stage.)

### What each stage covers

| Stage | Step | Tool | Touches |
|---|---|---|---|
| check | report outdated Python/npm/base-image versions | `pip`, `npm`, docker | nothing |
| apply | re-pin Python packages | `pip` | `api/requirements.txt`, `pipeline/requirements.txt` |
| apply | update npm packages | `npm` (via Docker) | `frontend/package.json` |
| apply | pull latest base images | `docker compose pull` | local image cache |
| commit | rebuild + deploy images | `make up` (includes `--build`) | local images, running containers |
| commit | refresh + reload Suricata ET Open rules | `make rules` equivalent | `ids/suricata/rules/suricata.rules` |
| commit | commit + push dependency changes | `git` | only the files the apply stage edits |

### Workflow

1. `check` — review what's outdated.
2. Check any flagged `requirements.txt` pins before upgrading — some are pinned for compatibility reasons (e.g. `bcrypt==4.0.1` due to passlib 1.7.4 incompatibility with newer versions).
3. `apply` — update the pins and npm packages, pull new base images.
4. `commit` — rebuild and deploy the images (`make up`), refresh the Suricata rules, and commit + push the dependency bumps (only `requirements.txt` / `package.json` files; unrelated working-tree changes are left alone).

> Suricata rules can also be updated independently with `make rules`.

## Scheduled runs

A crontab entry runs the **full cycle** (check → apply → commit) on the **1st of every month at 07:00** (installed by `deploy/setup.sh`, an hour before the monthly report):

```
0 7 1 * * { bash /home/getarp-intel/maintenance/check-updates.sh check && bash /home/getarp-intel/maintenance/check-updates.sh apply && bash /home/getarp-intel/maintenance/check-updates.sh commit; } >> /home/getarp-intel/maintenance/logs/updates-$(date +\%Y-\%m).log 2>&1
```

The stages are chained with `&&`, so a failed apply never deploys or pushes a half-applied update. Logs are written to `maintenance/logs/updates-YYYY-MM.log` (one file per month, excluded from git).

To review the latest log:

```bash
cat maintenance/logs/updates-$(date +%Y-%m).log
```

### Reverting a bad update

The commit stage pushes each month's dependency bumps as a single
`Maintenance: dependency updates YYYY-MM-DD` commit, so if an update breaks
the app, roll back with:

```bash
git log --oneline -5                       # find the maintenance commit
git revert <maintenance-commit> && git push
bash maintenance/check-updates.sh commit   # rebuild + deploy on the reverted pins
```
