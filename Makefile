PYTHON ?= python3
export PYTHONPATH := src

.PHONY: test check privacy lint hooks

test:
	$(PYTHON) -m unittest discover -s tests

privacy:
	$(PYTHON) scripts/privacy_gate.py

# Everything that runs without extra installs: tests, byte-compile, privacy gate.
check: test
	$(PYTHON) -m compileall -q src scripts tests
	$(PYTHON) scripts/privacy_gate.py

# Needs the dev extras: pip install -e ".[dev]"
lint:
	ruff check .
	ruff format --check .
	mypy --strict src

hooks:
	sh scripts/install-hooks.sh
