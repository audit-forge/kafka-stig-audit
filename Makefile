.PHONY: test lint check-syntax smoke clean help

help:
	@echo "kafka-stig-audit — available targets:"
	@echo "  make test          Run all tests"
	@echo "  make lint          Syntax check all Python files"
	@echo "  make smoke         Run smoke test (direct mode, no broker needed)"
	@echo "  make clean         Remove generated output files"

test:
	python -m pytest test/ -v

lint:
	python -m py_compile audit.py runner.py
	python -m py_compile checks/base.py checks/auth.py checks/encryption.py
	python -m py_compile checks/authz.py checks/network.py checks/logging_checks.py
	python -m py_compile checks/zookeeper.py checks/container.py checks/cve_scanner.py
	python -m py_compile mappings/frameworks.py
	python -m py_compile output/report.py output/sarif.py output/bundle.py
	@echo "Syntax OK"

check-syntax: lint
	python -c "from checks import ALL_CHECKERS; print(f'Checkers loaded: {len(ALL_CHECKERS)}')"
	python -c "from mappings.frameworks import FRAMEWORK_MAP; print(f'Mappings: {len(FRAMEWORK_MAP)}')"
	python -c "from runner import KafkaRunner; print('Runner OK')"

smoke:
	python audit.py \
		--mode direct \
		--host localhost \
		--port 9092 \
		--skip-cve \
		--json output/smoke-results.json \
		--csv output/smoke-results.csv \
		--sarif output/smoke-results.sarif \
		--quiet || true
	@python -c "\
import json; \
doc = json.load(open('output/smoke-results.json')); \
print(f'Checks: {len(doc[\"results\"])} | Risk: {doc[\"summary\"][\"risk_posture\"]}') \
"

clean:
	rm -f output/*.json output/*.csv output/*.sarif output/*.zip
	rm -rf __pycache__ checks/__pycache__ mappings/__pycache__ output/__pycache__
	rm -rf .pytest_cache
	find . -name "*.pyc" -delete
