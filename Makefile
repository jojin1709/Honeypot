# Honeypot Lab — Makefile
.PHONY: start stop restart dashboard status test help

VENV = venv
PYTHON = $(VENV)/bin/python3
ifeq ($(OS),Windows_NT)
    PYTHON = $(VENV)\Scripts\python
    RM = del /q
else
    PYTHON = $(VENV)/bin/python3
    RM = rm -f
endif

help:
	@echo "🍯 Honeypot Lab Makefile"
	@echo "  make start      — Start all honeypots"
	@echo "  make stop       — Stop all honeypots"
	@echo "  make restart    — Restart all honeypots"
	@echo "  make dashboard  — Open web dashboard"
	@echo "  make status     — Check honeypot status"
	@echo "  make test       — Run attack simulator"
	@echo "  make analyze    — Run log analyzer"
	@echo "  make install    — Install dependencies"
	@echo "  make setup-notify — Configure notifications"

install:
	$(PYTHON) -m pip install -r requirements.txt
	@echo "✅ Dependencies installed"

start:
	$(PYTHON) start_all.py

stop:
	$(PYTHON) stop_all.py

restart: stop start

dashboard:
	$(PYTHON) dashboard.py

status:
	$(PYTHON) status.py

test:
	$(PYTHON) tools/test_scanner.py

analyze:
	$(PYTHON) tools/analyzer.py

setup-notify:
	$(PYTHON) features/notifications.py
