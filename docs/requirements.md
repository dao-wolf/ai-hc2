# AI HC2 requirements

Version 0.1, 30 Oct 2026. Status: draft for the maintainer's review.

AI HC2 (AI Harness Command Center) is one local place to see and steer every AI harness on a developer's machine:

- **What's installed:** each harness's version, and how healthy its setup is.
- **What's running:** sessions, models, processes and the resources they hold.
- **What to fix:** findings with a plain-English reason and a fix.

Deterministic code gathers, analyses and displays the data. LLMs, cloud or local, help analyse and fix through a controlled interface, and every step is logged.

## Scope

**In scope:**
- The harnesses listed under "Harness coverage".
- macOS first, then Linux.
- A local CLI, a web dashboard, a Mac menu bar and widget, and an MCP server.

**Out of scope for v1:**
- Reading conversation content.
- Changing any harness setting without approval.
- A hosted or cloud service.
- Windows.

**Users:**
- Primary: a developer running many parallel AI sessions across several harnesses.
- Secondary: open-source users and contributors.

## Terms

| Term | Meaning |
|---|---|
| Harness | A tool that runs an AI agent or chat, such as Claude Code, Codex or pi. |
| Session | One conversation or task in a harness. |
| Adapter | The code that knows where one harness keeps its data and how to read it. |
| Finding | Something worth knowing or fixing: a severity, a reason and a fix. |
| Proposal | A suggested action, from a rule, an LLM or a person. |
| Action | A catalogued operation HC2 can run, such as stopping a process tree. |
| Approval | A person's yes or no to a proposal. Only a person can approve. |
| Event | One line in the audit trail. |

## Harness coverage

From the discovery spike on 30 Oct 2026. "Live state" means HC2 can tell whether a session is running.

| Harness | First slice | Sessions | Live state | Notes |
|---|---|---|---|---|
| Claude Code CLI | S1 | Yes | Yes | |
| Claude desktop, Code tab | S1 | Yes | Yes | Embeds its own Claude Code version. |
| Claude desktop, Cowork | S1 | Yes | No | One shared VM process for all sessions. |
| Codex CLI, Codex desktop (ChatGPT app), VS Code extension | S8 | Yes | No | One shared store. The model is often missing. |
| pi | S8 | Yes | No | Its session format is documented. |
| Hermes Agent | S8 | Yes | No | |
| Ollama, and LM Studio when installed | S8 | Loaded models | n/a | Model memory via the local API. |
| Cursor IDE and Agent CLI | S8 | Partial | No | The folder is often missing. |
| Antigravity, Gemini app, VS Code AI extensions | S8 | No | n/a | Presence, version and resources only. |

## Functional requirements

| ID | Requirement |
|---|---|
| FR-1 Inventory | For each harness, show whether it's installed, its version or versions, and its install, config and docs locations. It must work offline and in under 5 seconds. |
| FR-2 Sessions | List each harness's sessions with: id, title (redactable), folder, model, created, last activity, state and origin (CLI, desktop or IDE). Show where each field came from and how reliable it is. The states are running-busy, running-idle, waiting, stale, ended and unknown. Running-busy, running-idle and waiting are shown only where the harness reports them (today only Claude Code does); otherwise the state is "running" or "unknown". |
| FR-3 Staleness | Flag sessions idle longer than a configurable time, and show what each one holds (memory, child processes). |
| FR-4 Resources | Show system pressure (memory, swap, load, thermal). For each harness and session, show the process tree: CPU, memory, GPU time, threads, age, listening ports and the role of each child (browser, dev server, test worker, MCP server, shell). |
| FR-5 Waste | Deterministic rules with configurable thresholds: memory pressure, idle sessions holding memory, orphaned processes, duplicate MCP servers, concurrent heavy test jobs, long-running hot processes, oversized app renderers, and a more powerful model than an idle or simple session needs (information only). |
| FR-6 Setup health | Port the existing instruction checks into per-harness rule packs: loading gaps, duplicate rules, plugin staleness, hooks, scheduled tasks and conflicting colour keys. Add drift checks across harnesses, for example CLAUDE.md against AGENTS.md, or against a fingerprint of instructions pasted into another app. |
| FR-7 Versions | Compare installed and latest versions, using machine-readable sources (npm, GitHub releases, app update feeds). Show every installed copy, such as a CLI and a desktop-embedded version of the same harness. |
| FR-8 Docs awareness | Fetch and fingerprint each harness's docs index (llms.txt) and changelog. Record which docs version each adapter and rule was checked against. Raise a finding when they change. An LLM review (FR-12) then explains the impact and proposes updates. |
| FR-9 Findings | Each finding has a severity (red, amber, info or green), an id that doesn't depend on file paths, and a title, location, reason and fix. A person can acknowledge findings, with a note and an optional expiry. That is an approver action, so an agent can't silence a red finding. Show what changed since the last scan, and keep history. |
| FR-10 Proposals and actions | Rules, LLMs or people can propose actions. The v1 catalogue: stop a process tree, stop a dev server on a port, open a file or folder, and rescan. Later: archive a session (where a harness allows it) and apply a text patch to an instruction file. Each action has a preview, approval, execution, a check that it worked, and a recorded result. Nothing runs without approval. |
| FR-11 Audit trail | Record every scan, finding change, proposal, approval or rejection, action, result, LLM tool call and config change. Each record has a time, an actor (system, person, or a named LLM client and model), a plain-English summary and trace ids. |
| FR-12 LLM interface | An MCP server (stdio first, local HTTP later). Read tools: status, findings, sessions, resources, versions, docs changes and audit search. Write tools are limited to proposals and notes, with no approval or execution over MCP. Every CLI command offers `--json`. Include prompt templates for the standard workflows: triage, docs review and optimise. |
| FR-13 Collaboration | Each finding and proposal has a notes thread. People and several LLM clients can add notes at the same time. Every note is attributed, and disagreements stay visible. HC2 never turns an LLM's opinion into a fact. |
| FR-14 Surfaces | **CLI.** **Local web dashboard:** overview, harnesses, sessions, resources, findings, proposals and approvals, audit log, versions and docs. **Mac menu bar and widget:** status, top findings, pending approvals. Optional notifications for new red findings. |
| FR-15 Telemetry | Export the audit trail as OpenTelemetry-compatible JSON lines, and push it over OTLP/HTTP if switched on. Any OTLP credentials are read from an environment variable named in the config; HC2 never stores them. Later: a local OTLP receiver that ingests harness telemetry (Claude Code, Codex), only after the user agrees to the harness config change. |
| FR-16 Configuration | Discover settings first. Keep the config file in the user's config folder: confidential folders, per-rule switches and thresholds, per-adapter switches and retention. Commit an example config. `hc2 doctor` validates the setup. |
| FR-17 Plan view | An optional, off-by-default view of a personal plan file: workstreams, decisions and phases. |

## Non-functional requirements

### Security

- **S-1 Local only.** Every listener binds to 127.0.0.1. Pages are served as `http://localhost:<port>`, because passkeys need a domain name rather than an IP address. Outbound network is opt-in, and only to an allow-list of docs and version hosts. Nothing is sent anywhere by default.
- **S-2 Least privilege.**
  - Scanners only read.
  - Executors run only catalogued actions with validated parameters.
  - Before stopping a process, re-check that it is still the same one: process id, start time and command fingerprint.
- **S-3 No secrets.**
  - Never read other processes' environment variables, keychains, credential files or token caches.
  - Command lines can hold secrets and private paths. HC2 keeps only the executable name and flag names, plus a fingerprint of the full line for identity checks.
  - File lists from `lsof` are used only for working folders and listening ports, and are redacted like any other path.
  - Anything that looks like a secret in captured text is redacted.
- **S-4 Prompt injection.**
  - Everything that comes from a harness or the web is data: titles, docs, file names.
  - An LLM can only create proposals and notes.
  - Approvals come only from the human surfaces.
- **S-5 Supply chain.**
  - Standard library first, with pinned and hashed dependencies.
  - CodeQL, Dependabot, secret scanning with push protection, OpenSSF Scorecard, zizmor and actionlint.
  - Build provenance on releases.
- **S-6 Threat model.** Kept up to date in `docs/threat-model.md`.
- **S-7 Tamper visibility.** Any change to the config, rule switches, thresholds, the confidential-folder list or the passkey list raises a finding that every surface shows. This holds even when the change was made outside HC2, because an agent can edit files.
- **S-8 Tamper evidence.**
  - Each approval stores its passkey assertion. The executor re-verifies it against the registered key just before running.
  - `audit.jsonl` is hash-chained, so editing or deleting a single record breaks the chain and raises a finding.
  - A full rewrite with recomputed hashes needs anchors to show:
    - every approval challenge includes the current chain head, so each passkey assertion signs the log as it stood then;
    - the Mac app keeps its own record of the last chain head, the passkey-list fingerprint and whether setup has run, and shows red ("HC2's history was reset or rewritten") if any of them goes backwards or disappears.
- **S-9 Honest scope.**
  - An agent with a shell can act directly, outside HC2: kill processes, edit files. HC2 can't prevent that.
  - HC2 guarantees two things: it acts only on a person's verified decision, and tampering with its state is visible. The threat model says so plainly.
  - The anchors in S-8 raise the bar rather than close the gap. An agent that knows about them could also edit the Mac app's stored record.

### Authentication and authorisation

- **A-1 HTTP access.** The web UI and HTTP API require a random per-install token on every request. The token is stored in a file only the user can read. Host and Origin headers are checked, which stops DNS rebinding and cross-site requests. No CORS.
  - A request with no Origin, from a native client, is allowed. A request whose Origin isn't the server's own is refused.
  - The token grants Viewer and Proposer only. Any process running as the user can read it, so it can never approve.
- **A-2 Roles.**

  | Role | Can | Who |
  |---|---|---|
  | Viewer | Read | Anyone holding the token |
  | Proposer | Read, propose and add notes | Anyone holding the token, including MCP clients |
  | Approver | Approve or reject proposals, acknowledge findings, and change config through HC2 | Only a person, proven by a presence check that another process running as the same user can't produce (A-4) |

- **A-3 MCP.** MCP over stdio runs as the local user. MCP over HTTP (later) needs the token and a client name.
- **A-4 Proof of presence.**
  - Every approver action needs a passkey assertion (WebAuthn with user verification). The assertion signs that exact decision: the proposal ids, a hash of each preview, a nonce and an expiry.
  - Any passkey with user verification works:
    - Touch ID;
    - the Mac login password, on Macs without Touch ID;
    - a phone over a QR code (Face ID or fingerprint);
    - a hardware security key with a PIN.
  - For someone with none of these, an opt-in "unprotected approvals" mode allows a plain click. It shows a permanent red finding on every surface while it's on, because any agent could then approve.
  - One assertion can cover a batch of decisions.
  - Challenges can be used once only and expire within minutes.
  - A changed proposal, a replayed approval or an expired one is refused.
  - **Registering passkeys.**
    - The person registers the first passkey in `hc2 setup`. That first registration is trusted on first use.
    - That no-check path is open only while `hc2 setup` runs in an interactive terminal, for 5 minutes at most. It is never open through `hc2 serve`.
    - Adding another passkey needs an existing one.
    - Any change to the passkey list raises a finding on every surface, and it can't be acknowledged for 7 days.
  - The CLI and the Mac app hand the presence step to the web page. They never approve on their own.
  - No URL or link ever approves anything.

### Privacy

- **P-1 Metadata only.**
  - HC2 never extracts, keeps, logs, displays or sends conversation text.
  - Adapters may read named metadata fields from session records: id, title, model, timestamps, folder and status.
  - Reads are bounded, for example the first and last few hundred KB of a file. Everything else read is discarded in memory.
  - Each adapter lists the exact fields it reads, and a test proves message text never reaches its output.
- **P-2 Confidential folders.**
  - Always shown as "Confidential A", "Confidential B" and so on, in every surface. There is no setting that reveals them.
  - Their titles and paths never appear in any surface, log, export or LLM payload.
- **P-3 Redact at the core.** Redaction happens in the core, before data reaches a surface, a log or an LLM.
- **P-4 No personal data in the repo.** A privacy gate in pre-commit and CI checks every change against a personal deny-list that is kept outside the repo.

### Determinism

- **D-1 Same in, same out.** The same inputs give the same outputs: sorted, with stable ids and no clock time in ids.
- **D-2 No LLM in the scan.** LLMs never run as part of the scan.
- **D-3 Labelled sources.** LLM content is always labelled with its source.

### Performance and footprint

- **F-1 Speed.** A full scan takes 5 seconds or less offline, and each resource sample 2 seconds or less.
- **F-2 Footprint.**

  | Component | CPU when idle | Memory |
  |---|---|---|
  | Core | 1% or less | 150 MB or less |
  | Menu bar app | n/a | 80 MB or less |

- **F-3 Shared Mac.** Never start heavy work while the user's own heavy jobs run. A configurable lock file controls this.

### Reliability

- **R-1 Isolation.** One adapter failing never breaks the scan. It reports "unknown" with a reason.
- **R-2 Tolerant parsers.** Unknown or missing fields become null. A format change raises an "adapter needs update" finding rather than crashing.
- **R-3 Versions.** Contracts carry versions: a JSON schema version, and MCP tool versions.

### Configurability

- **C-1 Precedence.** A CLI flag beats an environment variable, which beats the config file, which beats the defaults.
- **C-2 Thresholds and adapters.** Every threshold is configurable, and adapters plug in.

### Testability

- **T-1 Test types.**
  - Unit tests for each adapter, using made-up fixtures with no real personal data.
  - Golden tests for rules.
  - Contract tests for the JSON schema and the MCP tools.
- **T-2 Coverage.** At least 85% coverage of the core, plus mutation testing on the rules.
- **T-3 Interface tests.** End-to-end tests for the web UI, with at most 2 browser workers and accessibility checks included. Swift unit tests for the Mac app's models.
- **T-4 Privacy tests.** Sentinel strings planted in fixtures must never appear in any output.

### Accessibility

- **X-1 Standard.** The web UI meets WCAG 2.2 AA.
- **X-2 More than colour.** Status is never shown by colour alone: there's always an icon and text.
- **X-3 Keyboard and screen readers.** Everything works by keyboard. The web UI and the Mac app have screen-reader labels.
- **X-4 CI.** axe-core runs in CI.

### Observability

- **O-1 Own records.**
  - `audit.jsonl` uses OpenTelemetry LogRecord field names, with a plain-English body on each record.
  - HC2 tracks its own metrics: scan time, adapter errors, and findings by severity.
- **O-2 Export.** OTLP/HTTP export is opt-in. The format can be ingested by the Grafana stack, Jaeger, SigNoz, Datadog, Honeycomb, Langfuse and Phoenix.
- **O-3 Conventions.** OpenTelemetry GenAI names are used only for LLM and tool-call spans, because they are still in development. HC2's own events use `hc2.*`, and every record carries its schema version.

### Operability

- **Op-1 Install and errors.** Install with one command. `hc2 doctor` checks the setup and gives fix hints. Error messages say why, not just "failed".
- **Op-2 Retention.** Logs and snapshots rotate. The default keeps 30 days.
- **Op-3 Start and upgrade.** Starting at login is optional. Upgrades keep config and history.

### Maintainability

- **M-1 Structure.** Adapters and rule packs are modules with documented interfaces. Code is type-checked and linted.
- **M-2 Decisions.** Decisions are recorded as ADRs. PRs stay small.
- **M-3 Validation record.** Each adapter records the harness version and docs fingerprint it was checked against.

### Portability

- **Pt-1 Platforms.** macOS 14 or later first, then Linux for the core and web UI. OS-specific code is kept separate.

### Open source

- **OS-1 Licence and project files.** Licensed under Apache-2.0, with README, CONTRIBUTING, SECURITY and CODE_OF_CONDUCT files.
- **OS-2 Clean history.** History started clean, with no personal data in the repo.

## Acceptance

Each slice in [slices.md](slices.md) lists the requirements it delivers and its "done when" tests.
