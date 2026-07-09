# getarp.net Defence Intelligence PoC — operator shortcuts
.PHONY: help setup up down build logs ps restart rules bouncer enroll psql clean

help:
	@echo ""
	@echo "  First-time install:"
	@echo "    sudo bash deploy/setup.sh   — interactive setup (secrets, install, start)"
	@echo ""
	@echo "  Day-to-day:"
	@echo "    make up        build + start the whole stack"
	@echo "    make down      stop the stack"
	@echo "    make build     rebuild images without restarting"
	@echo "    make logs      tail all service logs"
	@echo "    make ps        show service health"
	@echo "    make restart   rolling restart of all services"
	@echo ""
	@echo "  Maintenance:"
	@echo "    make rules     pull/update Suricata ET Open rules, restart IDS"
	@echo "    make bouncer   register host firewall bouncer with CrowdSec LAPI"
	@echo "    make enroll T= enrol in CrowdSec community console (T=<token>)"
	@echo "    make psql      open a psql shell into the database"
	@echo "    make clean     DANGER: stop + remove all volumes (destroys data)"
	@echo ""

setup:
	sudo bash deploy/setup.sh

up:
	docker compose up -d --build

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f --tail=100

ps:
	docker compose ps

restart:
	docker compose restart

rules:
	docker compose exec suricata suricata-update -o /etc/suricata/rules
	docker compose restart suricata
	@echo "[✓] Suricata rules updated."

bouncer:
	@echo "Registering host firewall bouncer with CrowdSec LAPI..."
	sudo bash /usr/local/bin/getarp-register-bouncer

enroll:
	docker compose exec crowdsec cscli console enroll $(T)

psql:
	@. .env && docker compose exec postgres psql -U $$PG_USER -d $$PG_DB

clean:
	@echo "WARNING: This destroys all data. Press Ctrl-C to abort, Enter to continue."
	@read _
	docker compose down -v
