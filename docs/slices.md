# AI HC2 delivery slices

Version 0.1, 30 Oct 2026. Draft.

Each slice ships something usable on its own, and each one keeps every earlier slice working. Requirement ids refer to [requirements.md](requirements.md).

## Who builds what

| Lane | Owner |
|---|---|
| Requirements, design, reviews, privacy gate, integration | Orchestrator session |
| Core engine and web UI | Sonnet sub-agents, briefed and reviewed by the orchestrator |
| Mac menu bar and widget | The existing Mac app session |

## Slices

| Slice | Delivers | Requirements | Done when |
|---|---|---|---|
| **S0 Bootstrap** | Repo skeleton; Apache-2.0 licence; README, CONTRIBUTING, SECURITY and CODE_OF_CONDUCT; `pyproject.toml`; CI (ruff, mypy and tests on Python 3.11 and 3.12); CodeQL; Dependabot; Scorecard; zizmor and actionlint; a privacy gate (a script plus a CI step, with the deny-list read from outside the repo); docs | OS-1, OS-2, S-5, P-4 | `make check` passes locally. The privacy gate passes. The public repo is created and pushed. CI is green. |
| **S1 Core and Claude** | Model, redaction, store, audit log v1; `hc2 scan`, `status` and `sessions --json`; adapters for the Claude Code CLI, the desktop Code tab and Cowork; installed versions | FR-1, FR-2, FR-9 (part), FR-11 (part), P-1 to P-3, D-1, R-1, R-2 | On the maintainer's Mac, `hc2 sessions --json` lists Claude sessions, and the real-data check (counts only) shows 0 confidential leaks. Fixture tests pass with at least 85% coverage of the core. |
| **S2 Resources** | Process trees, system pressure, waste rules (thresholds from the spike); `hc2 resources` | FR-3, FR-4, FR-5 | The rules fire correctly on recorded fixtures. A live run takes 2 seconds or less. HC2 never reads other processes' environments (a test enforces this). |
| **S3 Setup health** | The Claude Code rule pack, ported from AI Harness Health; cross-harness drift | FR-6 | Golden tests on fixtures match the old engine's findings. |
| **S4 Web dashboard (read-only)** | HTTP API with token, Host and Origin checks; web pages for overview, harnesses, sessions, resources and findings | FR-14, A-1, X-1 to X-4 | Security tests: no token, a wrong Origin or a wrong Host all get rejected. axe finds 0 violations. Keyboard-only walkthrough passes. |
| **S5 Mac app on the API** | Menu bar and widget read schema 2 from the API, found through `api.json`; badge for pending approvals. The app only connects. Until S11, `hc2 serve` is started by hand, and the old app stays installed so there's no gap. | FR-14 | The app needs only the API address and token, and never runs scripts or knows where Python is. It shows clear states for: API down, wrong token, schema mismatch and SSE reconnecting. Swift tests decode the same schema 2 fixtures as the Python contract tests. The app keeps its own anchor: the last chain head, the passkey-list fingerprint and whether setup has run. It shows red if any of them goes backwards or disappears. |
| **S6 Proposals and MCP** | Action catalogue v1 (stop a process tree, stop a port's server, open, rescan); passkey approvals (A-4); the CLI and Mac app hand off to the web approve page; audit trail viewer; MCP server with read and propose tools. Starts with a spike: passkeys on `http://localhost`. | FR-10, FR-11, FR-12, A-2, A-3, A-4, S-2, S-4, S-7, S-8 | An end-to-end trace runs proposal → passkey approval → action → result. These are refused: a request holding the token but no passkey check (a test acting as an agent with shell access), a changed preview, a reused challenge, an expired approval, a stale process id, an approval row inserted straight into the database, and a passkey registered without an existing one. Editing an audit line breaks the hash chain and raises a finding. |
| **S7 Versions and docs** | Latest-version checks; docs fingerprints; the docs-review workflow over MCP; adapters record what they were checked against | FR-7, FR-8 | Fixture feeds give the right "behind by" findings. A docs change raises a finding. Network access is limited to the allow-list. |
| **S8 More harnesses** | Codex (CLI, desktop, VS Code), pi, Hermes and Ollama/LM Studio first; then Cursor, Antigravity, the Gemini app and the VS Code extensions | FR-1, FR-2, FR-4 | Each adapter has fixtures, a validated-against record, and a privacy test. |
| **S9 Telemetry** | OTLP/HTTP export; an optional local receiver for Claude Code and Codex telemetry, switched on through an approved proposal | FR-15, O-1 to O-3 | The record appears in a local Grafana or Jaeger, with the setup documented. |
| **S10 Collaboration** | Notes threads, attribution for several LLMs, a local model through an MCP-capable client | FR-13 | Two LLM clients add notes to one finding, and both are attributed in the audit trail. |
| **S11 Packaging** | One-command install, start at login, retention, upgrade path, signed Mac app | Op-1 to Op-3 | A fresh-machine install takes under 5 minutes, and `hc2 doctor` is clean. |

## Test strategy

- **Fixtures.**
  - Made up, never copied from a real machine.
  - Each harness's fixtures mimic its real format and plant sentinel strings.
  - Privacy tests check that the sentinels never appear in any output.
- **Test levels.**

  | Level | What it covers |
  |---|---|
  | Unit | Each adapter and each rule |
  | Golden | Rule packs |
  | Contract | JSON schema and MCP tools |
  | End-to-end | Web UI, with at most 2 browser workers |
  | Swift | Mac app models |

- **Live checks.** On the maintainer's Mac, read-only and printing counts only. These are never part of CI.
- **Mutation testing.** Rule packs, from S3 on.
- **Running tests locally.**
  - The standard-library test runner, so contributors need only Python 3.11 or later.
  - CI adds ruff, mypy and coverage.
  - Heavy jobs go through the shared lock.
