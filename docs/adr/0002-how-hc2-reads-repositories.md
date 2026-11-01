# ADR 0002: How HC2 reads repositories

Status: proposed, 1 Nov 2026. It is accepted when the maintainer merges it.

Context: FR-18 adds an optional repository-health pack. It reads GitHub's APIs and the git clones on the user's machine. Both can expose secrets, run code or leak a user's security gaps if read carelessly. Research and the check list are in [research/repo-health.md](../research/repo-health.md).

| # | Decision | Chosen | Why | Rejected |
|---|---|---|---|---|
| 1 | Switch | Off by default, like FR-17. A user turns it on in their config. | Only people who own repositories need it, and it adds network calls. | On by default. |
| 2 | GitHub auth | Through the `gh` CLI on a fixed allow-list: `gh api` with an explicit `--method GET`, and `gh api graphql` for queries only, refusing any document that contains a mutation. Never `gh auth token`, `gh auth status --show-token` or any command that prints a credential. A timeout on every call; output parsed as JSON only. | `gh` keeps the token, so HC2 stores none, and a GET-and-query-only allow-list can't change a repo. | HC2 storing its own token; a GitHub App. |
| 3 | Fallback token | An environment variable named in the config. Sent only to `api.github.com`; never logged or stored. | Works where `gh` isn't installed, without HC2 keeping a secret. | A token in the config file. |
| 4 | Network | Opt-in, and only `api.github.com` and `api.scorecard.dev` (S-1). | The smallest set the checks need. | Any host a check names. |
| 5 | Schedule | The collector runs on its own schedule with a cache, outside the 5-second scan (F-1). It batches with GraphQL and uses ETags. | A trial took about 5 seconds per repository before batching. | Collecting inside every scan. |
| 6 | Local git | A fixed allow-list of reading commands, each with a timeout and with `--no-optional-locks`, `GIT_OPTIONAL_LOCKS=0`, `-c core.fsmonitor=false`, `-c core.hooksPath=/dev/null`, `--no-pager`, `GIT_PAGER=cat`, `GIT_TERMINAL_PROMPT=0` and `-c diff.external=`. No fetch, pull, write, diff or log commands. | A plain `git status` can rewrite the index and run configured commands. The settings switch off what git's manual documents. The allow-list is the main control for anything they miss (research page, section 8). | Calling git with default settings. |
| 7 | Confidential folders | Skipped entirely: no git command runs in them, and they show as "Confidential A: skipped" (P-2). | Even `git status` reads file names. Masking the output afterwards is too late. | Running git and masking the output. |
| 8 | Where results go | The user's state folder, the CLI, the local dashboard, and the MCP read tool for clients the user connects. Nothing is published. HC2 only reads repositories; a fix needs an approved proposal (FR-10). Private repo names are hidden unless the user opts in. | Health results are a map of a user's security gaps. | A public page or badge, for now. |
| 9 | Checks | Data in the user's config (`[[repo_checks]]`), built from a fixed list of tested kinds. A new kind is a code change with golden tests. | Users add checks without a release, and every check stays deterministic. | Free-form expressions; an LLM judging repos. |
| 10 | The HC2 repo itself | Holds no user's repository names, results or settings (OS-3). Its docs and fixtures use made-up data. | HC2 is a tool for anyone. | Real repositories as examples in the docs. |
