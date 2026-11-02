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

# Needs the mutation extra: pip install -e ".[mutation]". Takes about 10 minutes on
# one core. cosmic-ray edits files in place, so it runs on a copy in .mutation/ and
# your files are never changed. Survivors are mutants that no test caught.
mutation:
	rm -rf .mutation && mkdir .mutation && cp -R scripts tests cosmic-ray.toml .mutation/
	cd .mutation && cosmic-ray baseline cosmic-ray.toml \
		&& cosmic-ray init cosmic-ray.toml mutation.sqlite \
		&& cosmic-ray exec cosmic-ray.toml mutation.sqlite \
		&& cr-rate mutation.sqlite \
		&& cr-report --surviving-only --show-diff mutation.sqlite

hooks:
	sh scripts/install-hooks.sh
