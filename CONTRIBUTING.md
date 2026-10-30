# Contributing to AI HC2

Thanks for helping. AI HC2 is pre-alpha, so please open an issue to talk through anything bigger than a small fix before you start.

## Set up

You need Python 3.11 or later and git. Nothing else is needed to run or test HC2, because it uses only the standard library.

```sh
git clone <this-repo-url> ai-hc2
cd ai-hc2
make hooks    # installs the privacy-gate pre-commit hook
make check    # tests, byte-compile and privacy gate
```

For linting and type checks, install the dev tools in a virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
make lint     # ruff check, ruff format --check, mypy --strict src
```

## Tests

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

- Tests use `unittest` only.
- CI also runs `coverage`. The core needs at least 85% coverage.
- Every adapter and rule gets a test. Rules get golden tests.
- Tests must never read or write your real config or state folders. Point `HC2_CONFIG_DIR` and `HC2_STATE_DIR` at a temporary folder.

## The privacy gate

This repo is public, so personal data must never reach it. `scripts/privacy_gate.py` scans every tracked file, and every untracked file that git does not ignore, for:

- terms from your own **deny-list**, kept outside the repo;
- email addresses (except noreply and example.com ones);
- absolute home paths such as `/Users/<name>/` or `/home/<name>/`;
- common secret formats, such as AWS key ids, GitHub tokens and private key headers.

Create your deny-list at `~/.config/ai-hc2/privacy-denylist.txt`, or point `HC2_PRIVACY_DENYLIST` at another file. Put one term per line. Lines starting with `#` and blank lines are ignored. List the names of people, employers, clients, private projects and anything else that must not appear in public.

- A term made of letters, digits and spaces matches whole words, ignoring case. "Sam" does not match "sample".
- A term with `/`, `.`, `-` or other characters matches as a substring.
- The gate prints `file:line term#N`, where N is the term's line number in your deny-list. It never prints the term.

Never copy your deny-list into the repo, an issue or a pull request. Without a deny-list the gate runs only the generic checks and says so. CI uses a repository secret for the maintainers' list, which is not available to pull requests from forks. A maintainer re-runs the gate with the full list before merging.

## Made-up fixtures only

Test data and examples must be invented. Never copy a file, a session title, a path or a log line from a real machine, even after editing it.

- Use names such as `alice`, `Example Project` and `/home/alice/example-project`.
- Use `example.com` for domains and emails.
- Plant a sentinel string, such as `SENTINEL-TITLE-1`, wherever private data would sit. Privacy tests check that sentinels never appear in output.

## Pull requests

- Keep them small and about one thing.
- Explain why, not only what.
- Run `make check` (and `make lint` if you can) before you push.
- Record a decision that is hard to reverse as an ADR in `docs/adr/`.
- Write prose in plain English, in short sentences, with British spelling. Use commas, colons or full stops rather than dashes.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(adapters): read Example Harness session index
fix(cli): exit 1 when a config folder is a file
docs: explain the deny-list format
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, `build`, `chore`.

## Licence

By contributing, you agree that your contribution is licensed under the Apache License 2.0, as set out in section 5 of the [LICENSE](LICENSE).
