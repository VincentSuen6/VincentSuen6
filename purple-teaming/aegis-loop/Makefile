.PHONY: help up down install assess report clean logs

PYTHON := python3
VENV   := venv
PIP    := $(VENV)/bin/pip
RUNNER := $(VENV)/bin/python

help:
	@echo "AegisLoop — Purple Team Pipeline"
	@echo ""
	@echo "  make up        Spin up Docker infrastructure"
	@echo "  make down      Tear down containers"
	@echo "  make install   Create venv and install Python deps"
	@echo "  make assess    Run full offensive assessment suite"
	@echo "  make report    Parse WAF logs → Navigator layer + HTML report"
	@echo "  make logs      Stream WAF access log"
	@echo "  make clean     Remove generated artefacts"

up:
	docker compose up -d
	@echo "Waiting for health checks..."
	@sleep 10
	@docker compose ps

down:
	docker compose down

install:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

assess:
	$(RUNNER) -m aegisloop run

report:
	$(RUNNER) -m aegisloop report

logs:
	tail -f waf-logs/access.log

clean:
	rm -f reports/*.json reports/*.html
	rm -f navigator-data/purple_matrix.json
