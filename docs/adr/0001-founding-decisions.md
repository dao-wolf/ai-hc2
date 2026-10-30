# ADR 0001: Founding decisions

Status: accepted, 30 Oct 2026, by the maintainer.

| # | Decision | Chosen | Why | Rejected |
|---|---|---|---|---|
| 1 | Repo start | New public repo with clean history. Personal config, plan and acknowledgements live outside the repo. | The prototype's files and history held personal data. A fresh start can't leak it. | Rewriting the old history; private first, public later. |
| 2 | What HC2 may do | It proposes and a person approves. Every step is logged. | Useful without risk. Nothing runs unseen. | Read-only; automatic actions from an allow-list. |
| 3 | Surfaces | A cross-platform core, a local web UI, and a Mac menu bar and widget as a thin client. | Contributors on any OS can use it, and the Mac experience is kept. | Native Mac only; web only. |
| 4 | LLM link | An MCP server and a JSON CLI. HC2 holds no API keys. | Any MCP client, cloud or local, can work through it side by side, and approvals stay with the person. | HC2 calling LLM APIs itself. |
| 5 | Licence | Apache-2.0. | Permissive, with an explicit patent grant. | MIT. |
| 6 | Read depth | Metadata only. HC2 never reads conversation content. Confidential folders are masked. | Privacy by design. Enough for health, staleness and resource views. | Opt-in transcript reading. |
| 7 | Runtime | Python 3.11 or later, standard library first. Static web UI with no build step. | No installs needed to run or test it. Small attack surface. | A Go or Rust binary; a JavaScript framework. |
| 8 | Log format | `audit.jsonl` with OpenTelemetry LogRecord field names and a plain-English body; OTLP/HTTP export when switched on. | Easy to read and tail, and monitoring tools can ingest it. The OpenTelemetry GenAI conventions are still in development, so they're used only for LLM spans. | Raw OTLP JSON files only; a database only. |
