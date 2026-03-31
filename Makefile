.PHONY: test lint check-syntax smoke clean help

help:
	@echo "kafka-stig-audit — available targets:"
	@echo "  make test          Run all tests"
	@echo "  make lint          Syntax check all Python files"
	@echo "  make smoke         Run smoke test (direct mode, no broker needed)"
	@echo "  make clean         Remove generated output files"

PYTHON ?= python3

test:
	$(PYTHON) -m pytest test/ -v

lint:
	$(PYTHON) -m py_compile audit.py runner.py
	$(PYTHON) -m py_compile checks/base.py checks/auth.py checks/encryption.py
	$(PYTHON) -m py_compile checks/authz.py checks/network.py checks/logging_checks.py
	$(PYTHON) -m py_compile checks/zookeeper.py checks/container.py checks/cve_scanner.py
	$(PYTHON) -m py_compile mappings/frameworks.py
	$(PYTHON) -m py_compile output/report.py output/sarif.py output/bundle.py
	@echo "Syntax OK"

check-syntax: lint
	$(PYTHON) -c "from checks import ALL_CHECKERS; print(f'Checkers loaded: {len(ALL_CHECKERS)}')"
	$(PYTHON) -c "from mappings.frameworks import FRAMEWORK_MAP; print(f'Mappings: {len(FRAMEWORK_MAP)}')"
	$(PYTHON) -c "from runner import KafkaRunner; print('Runner OK')"

smoke:
	$(PYTHON) audit.py \
		--mode direct \
		--host localhost \
		--port 9092 \
		--skip-cve \
		--json output/smoke-results.json \
		--csv output/smoke-results.csv \
		--sarif output/smoke-results.sarif \
		--quiet || true
	@$(PYTHON) -c "\
import json; \
doc = json.load(open('output/smoke-results.json')); \
print(f'Checks: {len(doc[\"results\"])} | Risk: {doc[\"summary\"][\"risk_posture\"]}') \
"

clean:
	rm -f output/*.json output/*.csv output/*.sarif output/*.zip
	rm -rf __pycache__ checks/__pycache__ mappings/__pycache__ output/__pycache__
	rm -rf .pytest_cache
	find . -name "*.pyc" -delete
