# Contributing to AI HC2

Thanks for your interest. AI HC2 is pre-alpha, so pull requests are by invitation: only collaborators can open them. Bug reports and ideas are welcome as issues, and security problems go through [SECURITY.md](SECURITY.md). The rules below apply to everyone who changes the repo, including invited contributors and AI agents.

## Set up

You need Python 3.11 or later and git. Nothing else is needed to run or test HC2, because it uses only the standard library.

```sh
git clone <this-repo-url> ai-hc2
cd ai-hc2
make hooks    # installs the privacy-gate git hooks
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
- `make mutation` checks that the privacy gate's tests can fail. It changes one thing in a copy of `scripts/privacy_gate.py` at a time and runs the gate's tests, and a change that no test catches is a gap. Install it with `pip install -e ".[mutation]"`. It needs pytest, which the extra installs, and only for this check. It needs `fork` (POSIX; WSL on Windows). It is not part of CI.

## The privacy gate

This repo is public, so personal data must never reach it. `scripts/privacy_gate.py` scans every tracked file, and every untracked file that git does not ignore, for:

- terms from your own **deny-list**, kept outside the repo;
- email addresses (except noreply and example.com ones);
- home paths such as `/Users/<name>/`, `/home/<name>/` or a Windows user folder, and folders under `~` or `$HOME`. Hidden folders such as `~/.config` pass, and so do `Library`, `Applications` and folders that start with `example`;
- common secret formats, such as AWS key ids, GitHub tokens and private key headers.

`make hooks` installs three git hooks that run the gate. The pre-commit hook scans the staged copy of each file, which is what the commit will hold, and the name and email git will put on the commit. The commit-msg hook scans the commit message, leaving out the diff that `git commit -v` adds below it. The pre-push hook scans every commit the push would send: its message, its author and committer, the names of the files it touches and the lines it adds. It also checks the names of the branches and tags it pushes, and the message and tagger of an annotated tag. It catches what the other two never see, such as a cherry-picked commit, what a merge adds, and a term that one commit adds and a later commit removes. It reads only the commits being sent, so a hit already in the public history does not stop a new push. In CI, `--trust-author-emails` skips the generic email check on each commit's author and committer, because a contributor's own address on their commit is not a leak; the deny-list still checks both, and the message and files keep every check. `make check` scans the files on disk instead. `make privacy` scans the files on disk and then every commit on your branch since `origin/main` (change the base with `make privacy RANGE=base..HEAD`). It needs your deny-list: without one, run `make privacy GENERIC_ONLY=1`.

Create your deny-list at `~/.config/ai-hc2/privacy-denylist.txt`, or point `HC2_PRIVACY_DENYLIST` at another file. Put one term per line. Lines starting with `#` and blank lines are ignored. List the names of people, employers, clients, private projects and anything else that must not appear in public.

- A term made of letters, digits and spaces matches whole words, ignoring case. "Sam" does not match "sample".
- A term with `/`, `.`, `-` or other characters matches as a substring.
- In both kinds, a space, hyphen or underscore between words matches any run of them, even across a line break. So "Example Person" also matches "example-person" and a name wrapped onto the next line. The hit is reported on the line where the match starts.
- The gate prints `file:line term#N`, where N is the term's line number in your deny-list. It never prints the term. For a commit (`--range`, `--pre-push`) it puts the first 10 characters of the commit id in front, and shows `<message>`, `<author>` or `<committer>` where a file would be.
- Exit code 0 means clean, 1 means hits, and 2 means the gate could not run: any failure at all, such as an unreadable deny-list or a damaged staged file, exits 2. A scan that finished always ends with a summary line, `privacy gate: scanned ..., N hits.` If your script or hook never saw that line, treat the run as failed. A required deny-list (`--require-denylist`) that holds no terms also exits 2. A file over 5 MB is not scanned, so the gate names it and exits 2; `--allow-skipped` turns that into a notice for a file you have checked another way. Binary files (a NUL byte near the start) are only counted, and UTF-16 text with a byte order mark is scanned as text.

Never copy your deny-list into the repo, an issue or a pull request. The hooks that `make hooks` installs stop a commit when your deny-list is missing or empty, so a mistyped path cannot let a commit through unchecked. If you have no deny-list, run `make hooks GENERIC_ONLY=1`: those hooks check only emails, home paths and secrets, and say so on every commit. A gate run by hand without a deny-list also runs only the generic checks and says so. This repo's CI runs only the generic checks, on the files and on every commit a change adds: deny-lists stay on contributors' own machines, and the full check runs in the git hooks. The workflow can read a deny-list from the `HC2_PRIVACY_DENYLIST_B64` secret, but this repo doesn't set one. Before merging a pull request, a maintainer runs `make privacy` on its branch with their own list.

## Made-up fixtures only

Test data and examples must be invented. Never copy a file, a session title, a path or a log line from a real machine, even after editing it.

- Use names such as `alice`, `Example Project` and `/home/alice/example-project`.
- Use `example.com` for domains and emails.
- Plant a sentinel string, such as `SENTINEL-TITLE-1`, wherever private data would sit. Privacy tests check that sentinels never appear in output.

## Keep your own context out

AI HC2 is a tool for anyone (OS-3 in the [requirements](docs/requirements.md)). Don't add your own repository names, scan or health results, counts, settings, tool choices or decisions about your set-up to code, docs, examples or tests, even as an illustration. Describe lessons in general terms, and keep your results in your own config and state folders. Add your repository names to your deny-list so the gate catches slips.

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
