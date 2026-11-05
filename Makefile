PYTHON ?= python3
export PYTHONPATH := src

.PHONY: test check privacy lint mutation hooks

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

# Needs the mutation extra: pip install -e ".[mutation]". Takes about 2 minutes on
# 2 cores. It works on a copy in mutants/, so your files are never changed. The
# hook tests are left out (mutmut can't run them). The normal test run covers them.
mutation:
	rm -rf mutants
	mutmut run --max-children 2
	mutmut results

hooks:
	sh scripts/install-hooks.sh $(if $(GENERIC_ONLY),--generic-only)
