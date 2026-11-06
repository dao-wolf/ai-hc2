PYTHON ?= python3
export PYTHONPATH := src

.PHONY: test check privacy lint mutation hooks

test:
	$(PYTHON) -m unittest discover -s tests

# The whole branch: the files as they are now, then every commit RANGE adds,
# messages included. It needs your deny-list; with none, run it with
# GENERIC_ONLY=1 to check emails, home paths and secrets only.
RANGE ?= origin/main..HEAD
privacy_mode = $(if $(filter 1,$(GENERIC_ONLY)),--generic-only,--require-denylist)

privacy:
	$(PYTHON) scripts/privacy_gate.py $(privacy_mode)
	$(PYTHON) scripts/privacy_gate.py $(privacy_mode) --range $(RANGE)

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
	sh scripts/install-hooks.sh $(if $(filter 1,$(GENERIC_ONLY)),--generic-only)
