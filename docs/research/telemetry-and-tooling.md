# Research: audit format, harness telemetry and free tooling

Condensed from research done on 30 Oct 2026 from official docs, vendor repositories and registries. Source URLs are kept so each claim can be re-checked. Check them again before relying on a version number, because most change weekly.

**Flags.**
- **[DEV]** Marked Development or experimental by its owner.
- **[BETA]** Marked beta.
- **[UNVERIFIED]** Not confirmed from an official page.
- **[UNDOC]** Works today but is not a documented public interface.

This page feeds FR-15 (telemetry), O-1 to O-3 (observability) and S-5 (supply chain). The decision it supports is ADR 0001, decision 8.

---

## 1. The local audit format

### Status of the OpenTelemetry pieces

| Piece | Status | Source |
|---|---|---|
| OTLP protocol (traces, metrics, logs) | Stable. Profiles are Development. | https://opentelemetry.io/docs/specs/otlp/ |
| Logs data model (`EventName`, `TraceId`, `SpanId`, `Body`) | Stable | https://opentelemetry.io/docs/specs/otel/logs/data-model/ |
| OTLP JSON encoding (hex ids, integer enums, camelCase, 64-bit integers as strings) | Stable | https://opentelemetry.io/docs/specs/otlp/ |
| OTLP file exporter (JSON Lines) | **[DEV]** | https://opentelemetry.io/docs/specs/otel/protocol/file-exporter/ |
| Collector `otlpjsonfile` receiver | Alpha, **[DEV]** for profiles | https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/otlpjsonfilereceiver/README.md |
| GenAI semantic conventions (`gen_ai.*`) | **Everything is [DEV].** The docs moved to a new repository with no tagged release. | https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md and https://opentelemetry.io/docs/specs/semconv/gen-ai/ |
| Core semantic conventions (`error.type`, `server.*`) | Stable | https://github.com/open-telemetry/semantic-conventions/releases |
| `gen_ai.tool.call.arguments`, `gen_ai.input.messages` and similar content attributes | Opt-in and **[DEV]** | https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md |
| Events such as `gen_ai.client.inference.operation.details` | **[DEV]** | https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-events.md |
| `OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental` | **[UNVERIFIED]** in the primary spec | https://opentelemetry-python-contrib.readthedocs.io/en/latest/instrumentation-genai/openai.html |
| `gen_ai.provider.name` replaced `gen_ai.system` | Seen in the current spec | https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md |

**Consequence.** `gen_ai.*` will change. Use it only for LLM-call and tool-call spans, pin the version in every record, and keep HC2's own facts under `hc2.*`.

### Options compared

| Option | For | Against | Verdict |
|---|---|---|---|
| A. OTLP JSON lines (file-exporter spec) | Exact to the standard. A Collector can replay it. | Deeply nested, hard to read or `grep`, spec is **[DEV]**, receiver is alpha. | Good as an export, poor as the source of truth. |
| B. Flat JSONL with OTel LogRecord field names | Easy to read, tail, `jq`, diff and append to. Maps one to one onto OTel. A plain-English `body` shows straight in Loki. | Needs a small converter to reach trace backends. Custom, so not standard by itself. | **Best local source of truth.** |
| C. SQLite or DuckDB only | Fast queries. | Not tail-able or ingestible without an export. Weaker as a tamper-evident log. | Use as an index over B, not as the audit record. |
| D. CEF, Syslog, W3C Trace Context only | Fits some SIEM tools. | Loses the span tree. | Skip. |

### Recommendation

1. **Source of truth:** `audit.jsonl`, append-only, flat records with OTel LogRecord names (`timeUnixNano` as a string, `severityText`, `eventName`, hex `traceId` and `spanId`, a plain-English `body`, flat dotted `attributes`).
2. **Ship an exporter, not a second format.** Push live over OTLP/HTTP (default port 4318) to an endpoint the user sets, and offer a file export that follows the file-exporter spec.
3. **Plain English, deterministic.** The `body` is templated by HC2, not written by a model, so the audit trail never depends on an LLM.
4. **Tamper evidence** (HC2's addition, not OTel): a hash chain, with each record holding the hash of the one before.

Sources: https://opentelemetry.io/docs/specs/otel/logs/data-model/ , https://opentelemetry.io/docs/specs/otlp/ , https://grafana.com/docs/loki/latest/send-data/otel/ (Loki uses `Body` as the log line).

### Propose, approve, run, result

One trace per proposed action. The root span is HC2's. LLM and tool spans use `gen_ai.*`. Approval and result use `hc2.*`.

| Step | Shape | Key attributes |
|---|---|---|
| Whole action | Root span `hc2.action` | `hc2.action.id`, `hc2.action.kind`, `hc2.risk`, `hc2.summary` |
| LLM proposed it | Child span `chat {model}` plus event `hc2.action.proposed` | `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.usage.*` **[DEV]** |
| Person approved or rejected | Child span `hc2.approval` plus event `hc2.approval.decided` | `hc2.approval.decision`, `hc2.approval.channel`. No GenAI convention exists for human approval. |
| Action ran | Child span `execute_tool {tool}` | `gen_ai.operation.name=execute_tool`, `gen_ai.tool.name`, `gen_ai.tool.call.id` **[DEV]**. Arguments and results only if opted in and redacted. |
| Result | Event `hc2.action.result`, span status, `error.type` on failure | `hc2.result.outcome`, `hc2.rollback.hint` |
| Approval arrives hours later | Do not keep a span open. End the proposal trace, start a new trace for the run and add a span link. | Span links are in the stable trace API. |

Sources: https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md , https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md , https://opentelemetry.io/docs/specs/otlp/

---

## 2. Where the audit trail can go

Every backend below takes OTLP. HC2 would send OTLP/HTTP to `http://127.0.0.1:4318`.

| Backend | Signals | Local minimum | Licence and cost | Notes | Source |
|---|---|---|---|---|---|
| **Grafana `otel-lgtm`** (Collector, Grafana, Loki, Tempo, Mimir, Prometheus, Pyroscope) | Logs, traces, metrics | One container on ports 3000, 4317 and 4318. Mount a volume to keep data. | Free, Apache-2.0. Docs say dev, demo and test only. | Best all-round: the plain-English logs and the traces sit side by side. The exact `docker run` form is **[UNVERIFIED]**. | https://grafana.com/docs/opentelemetry/docker-lgtm/ , https://github.com/grafana/docker-otel-lgtm |
| **Loki** alone | Logs | Part of LGTM | Free | Needs `allow_structured_metadata: true`. Dots in attribute names become underscores. | https://grafana.com/docs/loki/latest/send-data/otel/ |
| **Tempo** alone | Traces | Part of LGTM | Free | | https://grafana.com/docs/tempo/latest/configuration/ |
| **Alloy** | Routing | Only needed to tail the file instead of pushing | Free, Apache-2.0 | `otelcol.receiver.filelog` is public preview. | https://grafana.com/docs/alloy/latest/reference/components/otelcol/otelcol.receiver.filelog/ |
| **Collector contrib `otlpjsonfile`** | All three | A Collector binary and a short config | Free | Alpha. Re-reads a whole file when it changes. | https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/otlpjsonfilereceiver/README.md |
| **Jaeger v2** | Traces only | One `docker run`, UI on 16686, in memory | Free, Apache-2.0 | No logs, so the audit sentences would not show. | https://www.jaegertracing.io/docs/latest/getting-started/ |
| **SigNoz** | Traces, logs, metrics **[UNVERIFIED]** | Its installer tool, Docker with 4 GB or more of memory | MIT except the `ee/` folder | Heaviest free option. | https://signoz.io/docs/install/docker/ , https://github.com/SigNoz/signoz/blob/main/LICENSE |
| **OpenObserve** | Logs, traces, metrics | One container, UI on 5080 | AGPL-3.0 | Single binary, light. | https://openobserve.ai/docs/quickstart/ , https://openobserve.ai/docs/ingestion/traces/opentelemetry/ |
| **Datadog** | Traces, metrics, logs | The Datadog Agent and an account | Paid SaaS with a limited free tier | Data leaves the machine. | https://docs.datadoghq.com/opentelemetry/setup/otlp_ingest_in_the_agent/ , https://www.datadoghq.com/pricing/ |
| **Honeycomb** | Traces, metrics, logs | No local install. Account and API key. | Cloud, with a free plan | Data leaves the machine. | https://docs.honeycomb.io/send-data/opentelemetry/ , https://honeycomb.io/pricing |
| **Langfuse** | Traces only | Docker Compose, sized for 4 cores and 16 GiB | MIT except `ee/` | HTTP only, no gRPC. LLM-centric: good for model calls, not the audit log. | https://langfuse.com/integrations/native/opentelemetry , https://langfuse.com/self-hosting/deployment/docker-compose |
| **Arize Phoenix** | Traces, plus evals and datasets | One `docker run` | Elastic License 2.0 (source-available, not OSI open source) | Whether it reads `gen_ai.*` is **[UNVERIFIED]**. | https://arize.com/docs/phoenix/self-hosting/deployment-options/docker , https://github.com/Arize-ai/phoenix/blob/main/LICENSE |
| **otel-desktop-viewer** | Traces, metrics, logs views | A Homebrew cask or one `docker run`. In memory. | Apache-2.0, pre-1.0, one maintainer | Lightest way to see data now. | https://github.com/CtrlSpice/otel-desktop-viewer |

**Practical pick.** Document **otel-desktop-viewer** (no setup) and **grafana/otel-lgtm** (full). Both are free and take plain OTLP/HTTP.

---

## 3. Native telemetry from the harnesses

### Claude Code (https://code.claude.com/docs/en/monitoring-usage)

| Item | Detail |
|---|---|
| Switch | `CLAUDE_CODE_ENABLE_TELEMETRY=1`. Off by default. |
| Exporters | `OTEL_METRICS_EXPORTER` (`otlp`, `prometheus`, `console`, `none`) and `OTEL_LOGS_EXPORTER` (`otlp`, `console`, `none`). |
| Endpoint and protocol | `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_PROTOCOL` (`grpc`, `http/json`, `http/protobuf`; no default), `OTEL_EXPORTER_OTLP_HEADERS`. |
| Metrics | `claude_code.session.count`, `.cost.usage`, `.token.usage`, `.lines_of_code.count`, `.commit.count`, `.pull_request.count`, `.active_time.total`, `.code_edit_tool.decision`. |
| Events | `user_prompt`, `api_request` (model, cost, tokens, duration), `api_error`, `api_refusal`, `tool_decision`, `tool_result`, `assistant_response`, `safety_event`. |
| Session id, model, cost, tokens | Yes. `session.id` is on every metric and event. |
| Privacy | Prompts, tool details, outputs and responses are redacted unless the matching `OTEL_LOG_*` switch is set. Standard attributes include a user email and account id, which HC2 should strip if it re-exports. |
| Traces | **[BETA]**. Off by default. Needs `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1`. Shell children inherit `TRACEPARENT`, and `claude -p` honours an incoming one. |
| Who can set it | A repository's `.claude/settings.json` cannot turn telemetry on or choose where it goes. User environment or managed settings can. |
| Names | `claude_code.*`, not `gen_ai.*`. HC2 maps them. |

### Claude desktop and Cowork (https://claude.com/docs/cowork/monitoring.md)

- **Plans:** Team and Enterprise only, set by an admin. A solo user cannot rely on it.
- **Scope:** Cowork sessions only. Code-tab sessions use the Claude Code telemetry above.
- **Signals:** Events only: prompt, response, tool result, API request and error, tool decision. Metadata only unless an admin lists content categories.
- **Traces:** **[BETA]**.
- **Verdict:** file reading stays necessary for Cowork.

### Codex CLI (https://learn.chatgpt.com/docs/config-file/config-advanced ; `developers.openai.com/codex/...` redirects here)

| Item | Detail |
|---|---|
| Config | `~/.codex/config.toml`, table `[otel]`: `environment`, `exporter` (`none`, `otlp-http` or `otlp-grpc`), `log_user_prompt` (default false). A project-level config cannot set it. |
| Events | `codex.conversation_starts`, `api_request`, `sse_event` (token counts), `websocket_request`, `websocket_event`, `user_prompt`, `tool_decision`, `tool_result`. |
| Metrics | Counters and duration histograms, such as `codex.turn.token_usage` and `codex.tool.call`. |
| Session id, model, tokens | Yes. No cost field is documented. |
| Protocol | Docs show only binary protobuf, so a receiver needs protobuf support. |
| Traces | Not documented. |

### Gemini CLI (https://geminicli.com/docs/cli/telemetry/)

| Item | Detail |
|---|---|
| Config | `settings.json` `telemetry` or `GEMINI_TELEMETRY_*`: `enabled` (default false), `target`, `otlpEndpoint`, `otlpProtocol` (gRPC by default), `outfile`, `traces`, `logPrompts`. |
| Events and metrics | `gemini_cli.*` plus some `gen_ai.client.*` metrics. |
| Traces | Opt-in. Uses `gen_ai.*` **[DEV]**. |
| Session id, model, tokens | Yes. No cost. |
| Privacy | **`logPrompts` defaults to true**, the opposite of Claude Code and Codex. HC2 should set it false when it configures Gemini. |

### Others

| Harness | Native OTel? | What exists instead | Source |
|---|---|---|---|
| **pi** | No OTLP exporter. A telemetry package defines vendor-neutral contracts with no exporter. | Documented, versioned JSONL sessions that HC2 should parse. | https://github.com/earendil-works/pi/tree/main/packages/telemetry , https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/session-format.md |
| **Ollama** | None | A log file and `OLLAMA_DEBUG=1`. | https://docs.ollama.com/troubleshooting |

### Can HC2 run a local OTLP receiver instead of parsing files?

**Partly. Make it the main path for three harnesses and keep file parsing as the fallback.**

| Question | Answer |
|---|---|
| Works for | Claude Code (CLI, SDK, Code tab), Codex CLI and Gemini CLI. Claude Code also gives cost and the approval decision (`tool_decision`), which suits the audit trail. |
| Does not cover | pi, Ollama, Cowork for non-admin users, and anything that happened before telemetry was switched on. |
| Receiver design | Bind to 127.0.0.1:4318 only. Accept HTTP/JSON and HTTP/protobuf. Tell Gemini to use HTTP. |
| Setup cost | HC2 must edit each harness's config. That changes the user's tools, so HC2 shows the exact diff and asks first. Repository-level settings cannot do it for Claude Code or Codex. |
| Privacy | Claude Code and Codex redact prompts by default. Gemini does not. HC2 writes the safe settings and never turns on prompt capture without explicit consent. |
| Stability | Claude Code traces and Cowork traces are **[BETA]**. Field names are vendor-specific and have changed between versions, and many are version-gated. HC2 needs a per-vendor mapping layer and version-aware tests. |
| Bonus | Claude Code passes `TRACEPARENT` to shell children, so HC2 can parent a run under its own action span. |

Source for the receiver advice: https://docs.datadoghq.com/opentelemetry/setup/otlp_ingest_in_the_agent/ (advises localhost for local use) and https://code.claude.com/docs/en/monitoring-usage .

---

## 4. Docs and version awareness

For FR-7 and FR-8. Versions are deliberately left out of this table. Read them at run time from the sources shown.

| Product | Official docs | llms.txt | Changelog | Machine-readable latest version |
|---|---|---|---|---|
| **Claude Code** | https://code.claude.com/docs | https://code.claude.com/docs/llms.txt and `llms-full.txt` | https://code.claude.com/docs/en/changelog (RSS at `/docs/en/changelog/rss.xml`), https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md | npm `@anthropic-ai/claude-code` (tags `latest`, `stable`, `next`): https://registry.npmjs.org/@anthropic-ai/claude-code ; GitHub releases: https://api.github.com/repos/anthropics/claude-code/releases/latest ; Atom: https://github.com/anthropics/claude-code/releases.atom ; native installer pointer `https://downloads.claude.ai/claude-code-releases/latest` **[UNDOC]** |
| **Claude apps (desktop, Cowork)** | https://support.claude.com and https://claude.com/docs | https://support.claude.com/llms.txt , https://claude.com/docs/llms.txt , https://platform.claude.com/llms.txt | https://support.claude.com/en/articles/12138966-release-notes (dated, no build numbers) | macOS update feed `https://downloads.claude.ai/releases/darwin/universal/RELEASES.json` **[UNDOC]** ; Homebrew cask API `https://formulae.brew.sh/api/cask/claude.json` ; deployment guide https://support.claude.com/en/articles/12611117-deploy-claude-desktop-for-macos |
| **Codex CLI** | https://developers.openai.com/codex (redirects to https://learn.chatgpt.com/docs) | https://developers.openai.com/codex/llms.txt and `llms-full.txt` | https://learn.chatgpt.com/docs/changelog , https://github.com/openai/codex/blob/main/CHANGELOG.md | GitHub releases: https://api.github.com/repos/openai/codex/releases/latest ; npm `@openai/codex` (read the `latest` tag only, because the package has many alpha tags): https://registry.npmjs.org/@openai/codex |
| **Gemini CLI** | https://geminicli.com/docs | https://geminicli.com/llms.txt (no separate `llms-full.txt`) | https://geminicli.com/docs/changelogs/ | npm `@google/gemini-cli` (tags `latest`, `preview`, `nightly`): https://registry.npmjs.org/@google/gemini-cli ; Atom: https://github.com/google-gemini/gemini-cli/releases.atom |
| **pi** | https://pi.dev/docs/latest ; Markdown source in the repo under `packages/coding-agent/docs/` | None. Use the repo's `docs/` folder. | https://github.com/earendil-works/pi/blob/main/packages/coding-agent/CHANGELOG.md | npm `@earendil-works/pi-coding-agent`: https://registry.npmjs.org/@earendil-works/pi-coding-agent ; GitHub releases. The old repository and old npm scope are stale. |
| **Ollama** | https://docs.ollama.com | https://docs.ollama.com/llms.txt and `llms-full.txt` | None for docs. Use https://github.com/ollama/ollama/releases | GitHub releases: https://api.github.com/repos/ollama/ollama/releases/latest ; Atom: https://github.com/ollama/ollama/releases.atom |
| **OpenTelemetry** | https://opentelemetry.io/docs ; GenAI conventions at https://github.com/open-telemetry/semantic-conventions-genai | https://opentelemetry.io/llms.txt (index only) | https://github.com/open-telemetry/opentelemetry-specification/blob/main/CHANGELOG.md | GitHub releases for the specification, semantic conventions and Collector. The GenAI repository has no releases yet. |

Unauthenticated GitHub API calls are limited to 60 an hour. Prefer Atom feeds and the npm registry, and cache with ETags.

---

## 5. Free tools for a public GitHub repository

"Free" means free for a public repository.

| Tool | What it does | Limits and setup | Overlap | Source |
|---|---|---|---|---|
| **CodeQL** | Semantic SAST for Python, Swift (needs a macOS runner), JavaScript and TypeScript, and GitHub Actions workflows. | Free for public repositories. A click in Settings, or about 20 lines of YAML. | Semgrep, Sonar | https://docs.github.com/en/code-security/getting-started/github-security-features , https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/ |
| **Dependabot** | Alerts, security updates and version updates for pip, SwiftPM, npm, GitHub Actions and more. | Free. Alerts are a toggle. Updates need `.github/dependabot.yml`. A default cooldown applies to version updates. | Renovate | https://docs.github.com/en/code-security/reference/supply-chain-security/supported-ecosystems-and-repositories |
| **Secret scanning and push protection** | Blocks known secret formats at `git push` and alerts on leaks. | Free for public repositories. Enable it in Settings. | gitleaks | https://github.blog/news-insights/product-news/push-protection-is-generally-available-and-free-for-all-public-repositories/ , https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection |
| **OpenSSF Scorecard** | Scores repository hygiene from 0 to 10 and gives a badge. | Free. One workflow. Needs `id-token: write` to publish results. | Checks for CodeQL, Dependabot and zizmor | https://github.com/ossf/scorecard-action |
| **zizmor** | Static security analysis of workflow files: template injection, unpinned actions, excessive permissions. | Free, MIT. A workflow step or a pre-commit hook. | Scorecard's token-permission and pinned-dependency checks | https://docs.zizmor.sh/ , https://github.com/zizmorcore/zizmor |
| **actionlint** | Lints workflow syntax, expression types and shell in `run:` steps. | Free, MIT. One binary. | Small overlap with zizmor | https://github.com/rhysd/actionlint |
| **Codecov** | Coverage upload, pull-request comments and a badge. | Free for open source. Token rules **[UNVERIFIED]**. | Sonar | https://about.codecov.io/pricing/ , https://github.com/codecov/codecov-action |
| **Artifact attestations** (`actions/attest`) and SLSA | Signed build provenance. Verify with `gh attestation verify`. Gives SLSA Build L2. | Free for public repositories. Needs `id-token` and `attestations` permissions. | `slsa-github-generator` (older) | https://docs.github.com/en/actions/concepts/security/artifact-attestations , https://github.com/actions/attest-build-provenance |
| **axe-core** | Accessibility rules run inside a browser test. | Free, MPL-2.0. A dependency and a few lines of test code. | pa11y | https://github.com/dequelabs/axe-core |
| **pa11y-ci** | Runs a list of URLs through pa11y in CI. | Free, LGPL-3.0. Needs the local UI running in CI. | axe-core | https://github.com/pa11y/pa11y-ci |
| **StepSecurity harden-runner** | Watches or blocks runner network egress. | Free community tier for public repositories on GitHub-hosted runners. Audit-only on macOS. | Scorecard (indirectly) | https://github.com/step-security/harden-runner |
| **pre-commit.ci** | Runs pre-commit hooks on pull requests and updates them weekly. | Free for open source. | Dependabot's pre-commit support | https://pre-commit.ci/ |
| **release-please** | Release pull request, changelog and version bump from Conventional Commits. | Free, Apache-2.0. Use the `simple` release type. | None | https://github.com/googleapis/release-please-action |
| **OpenSSF Best Practices badge** | Self-certified checklist. | Free. A web form, about an hour. | Scorecard checks for it | https://www.bestpractices.dev/en |
| **GitHub Pages** | Static docs hosting. | Free for public repositories, with size and build limits. | None | https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits |
| **OSV-Scanner** | Scans lockfiles against OSV.dev. | Free, Apache-2.0. | Dependabot alerts | https://google.github.io/osv-scanner/github-action/ |
| **Semgrep CE** | Pattern-based SAST. | Free to run. The rules licence restricts redistribution. No cross-file analysis. | CodeQL | https://docs.semgrep.dev/faq/overview |
| **SonarQube Cloud** | Code quality, security and coverage. | Free for public repositories. Per-language availability **[UNVERIFIED]**. | CodeQL | https://www.sonarsource.com/plans-and-pricing/sonarcloud/ |
| **gitleaks** | Secret scanner. | Free, MIT. Now security-patch-only. A successor, Betterleaks, exists. | Push protection | https://github.com/gitleaks/gitleaks , https://github.com/betterleaks/betterleaks |
| **Renovate** | Dependency update pull requests. | Free app or self-hosted. | Dependabot (pick one) | https://docs.renovatebot.com/getting-started/installing-onboarding/ |
| **Lighthouse CI** | Accessibility, performance and SEO scores. | Free, Apache-2.0. | axe rules inside | https://github.com/GoogleChrome/lighthouse-ci |

### Recommended core set

| # | Tool | Why |
|---|---|---|
| 1 | CodeQL | The only free SAST that covers Python, Swift, JavaScript and the workflow files in one. |
| 2 | Dependabot | Free and native. Keeps the action pins current. |
| 3 | Secret scanning and push protection | Stops a leak before it exists. Matters for a tool that sees keys in harness logs. |
| 4 | OpenSSF Scorecard | A public, third-party hygiene score. |
| 5 | zizmor and actionlint | Workflow files are the main supply-chain surface of a public repository. |
| 6 | Codecov | Coverage badge and pull-request diff. Not covered by anything else here. |
| 7 | `actions/attest` on release builds | Signed provenance, once a release workflow exists. |
| 8 | axe-core in the browser tests | Accessibility is the one gate the security tools do not provide. |

### Add when ready

pre-commit.ci (if the repository adopts pre-commit), GitHub Pages for docs, the OpenSSF Best Practices badge before 1.0, harden-runner in audit mode on Linux jobs, and release-please for changelogs.

### Skipped as redundant

SonarQube Cloud, Semgrep CE, OSV-Scanner, gitleaks, Renovate, Lighthouse CI and `slsa-github-generator`. Each repeats a tool above, or adds little for a local-only tool.
