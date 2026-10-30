# Harness data sources

Where each harness keeps the data HC2 reads, what that data holds, and how to find its version and docs. This comes from the discovery spike of 30 Oct 2026, and it feeds the adapters in S1 and S8.

HC2 reads metadata only (P-1). The "Fields HC2 reads" column lists the only keys an adapter may take from these files. Message and transcript content is never read.

## How to read this page

- **Confidence** says how well the format is established.
  - **High:** checked against real data on a real machine.
  - **Medium:** checked in part, or taken from official docs and seen to match.
  - **Low:** taken from upstream docs or source only. Not yet seen on a real machine.
- Paths use `~` for the home folder. `<...>` marks a part that varies.
- Version numbers are deliberately absent. They change weekly. The adapters read them at run time.
- Formats are not public interfaces unless a harness documents them. Every adapter must treat unknown or missing fields as null (R-2).
- Each adapter records the harness version and the docs fingerprint it was checked against (M-3).

## Summary

| Harness | First slice | Sessions | Live state | Confidence |
|---|---|---|---|---|
| Claude Code CLI | S1 | Yes | Yes | High |
| Claude desktop, Code tab | S1 | Yes | Yes | High |
| Claude desktop, Cowork | S1 | Yes | No | High |
| Codex CLI, Codex desktop (ChatGPT app), VS Code extension | S8 | Yes | No | High |
| pi | S8 | Yes | No | Medium |
| Hermes Agent | S8 | Yes | No | Medium |
| Ollama | S8 | Loaded models | n/a | Medium |
| LM Studio | S8 | Loaded models | n/a | Low |
| Cursor IDE | S8 | Partial | No | Medium |
| Cursor Agent CLI | S8 | No | No | Low |
| Antigravity | S8 | No | n/a | Medium |
| Gemini app | S8 | No | n/a | Medium |
| Gemini CLI | Later | Not confirmed | No | Low |
| Windsurf, Aider | Later | Not confirmed | No | Low |

## Claude Code CLI

| Item | Detail |
|---|---|
| Install | `claude` on the path. Usually a symlink into `~/.local/share/claude/versions/<version>`. |
| Version source | The real path of the `claude` symlink, which ends in the version. Fallback: `claude --version`. |
| State folder | `~/.claude` |
| Settings | `~/.claude/settings.json` |
| Sessions | `~/.claude/projects/<folder-encoded-as-dashes>/<sessionId>.jsonl`, one file per session. |
| Live registry | `~/.claude/sessions/<pid>.json`, written by every running `claude`. A file only counts if its `pid` is alive and the process name is `claude`, which also guards against recycled process ids. |
| Fields HC2 reads | From the head of the transcript: first timestamp, `cwd`, `entrypoint`, `version`. From title lines: `customTitle`, `agentName` or `aiTitle`, in that order. From the tail: last timestamp and the model name. From the registry: `sessionId`, `pid`, `status`, `statusUpdatedAt`, `name`, `cwd`, `startedAt`, `updatedAt`, `entrypoint`. |
| How it reads | Only a bounded slice at the start and end of each transcript, never the whole file. |
| Overlap | Sessions started by the desktop Code tab share this store. They have `entrypoint` set to the desktop app, or a matching `cliSessionId` in the desktop index. List them once, under the desktop harness. |
| Live state | Yes. The registry's `status` field, checked against the process table. |
| Docs | https://code.claude.com/docs |
| Changelog | https://code.claude.com/docs/en/changelog |
| llms.txt | https://code.claude.com/docs/llms.txt (and `llms-full.txt`) |
| Confidence | High |

## Claude desktop, Code tab

| Item | Detail |
|---|---|
| Install | `/Applications/Claude.app` |
| Version source | `Contents/Info.plist`, key `CFBundleShortVersionString`. |
| Embedded Claude Code | `~/Library/Application Support/Claude/claude-code/<version>/<hash>/claude.app`. Several versions can sit side by side, and they can differ from the CLI. Show each one (FR-7). |
| Session index | `~/Library/Application Support/Claude/claude-code-sessions/<account>/<organisation>/local_<uuid>.json` |
| Fields HC2 reads | `sessionId`, `cliSessionId`, `title`, `cwd`, `originCwd`, `model`, `createdAt`, `lastActivityAt` (both in milliseconds since the epoch), `isArchived`, `completedTurns`. |
| Transcripts | In the CLI store above, joined through `cliSessionId`. |
| Live state | Yes. A session is running when its `cliSessionId` appears in the live registry with a live process. |
| Docs | https://support.claude.com/en/collections/16163169-claude-code |
| Changelog | https://support.claude.com/en/articles/12138966-release-notes (dated notes, no build numbers) |
| llms.txt | https://support.claude.com/llms.txt |
| Confidence | High |

## Claude desktop, Cowork

| Item | Detail |
|---|---|
| Install | Same app bundle as the Code tab. |
| Version source | Same as the Code tab. |
| Session index | `~/Library/Application Support/Claude/local-agent-mode-sessions/<account>/<organisation>/local_<uuid>.json` |
| Session folders | `.../local_<uuid>/` hold the session's own files. HC2 does not read them. |
| VM | `~/Library/Application Support/Claude/vm_bundles`. One shared VM process serves every session. |
| Fields HC2 reads | `sessionId`, `title`, `model`, `createdAt`, `lastActivityAt`, `isArchived`, `sessionType`, `processName`, whether an `error` is set, and the first entry of `userSelectedFolders` as the folder. |
| Gotchas | The `cwd` key is a path inside the VM, not on the host. Use `userSelectedFolders`. |
| Live state | No. The process table shows only the shared virtualisation process, which other apps also use, so it is a hint at most. |
| Docs | https://support.claude.com and https://claude.com/docs |
| Changelog | Same release notes as the Code tab. |
| llms.txt | https://claude.com/docs/llms.txt |
| Confidence | High |

## Codex CLI, Codex desktop and VS Code extension

All three share one store.

| Item | Detail |
|---|---|
| CLI install | `codex` on the path. Usually a symlink into `~/.codex/packages/standalone/releases/<version>-<arch>/bin/codex`. |
| CLI version source | The real path of the symlink. Fallback: `codex --version`. |
| Desktop install | `/Applications/ChatGPT.app`, which is the Codex app (bundle id `com.openai.codex`), not a plain chat client. No separate chat store was found. |
| Desktop version source | `Contents/Info.plist`, key `CFBundleShortVersionString`. |
| State folder | `~/.codex` |
| Config | `~/.codex/config.toml` |
| Sessions | SQLite file `~/.codex/state_5.sqlite`, table `threads`. Open it read-only. The number in the file name is a schema version and may change. |
| Rollouts | `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl` (also compressed). These hold content. HC2 does not read them. |
| Name index | `~/.codex/session_index.jsonl` |
| Desktop UI state | `~/.codex/.codex-global-state.json`, and `~/Library/Application Support/Codex` |
| Fields HC2 reads | From `threads`: `id`, `name` (falling back to `title`), `cwd`, `model`, `created_at_ms`, `updated_at_ms`, `source`, `originator`, `archived`, `cli_version`. |
| Telling the surfaces apart | `originator` equal to "Codex Desktop" is the desktop app. `source` of `cli` or `exec` is the terminal. `source` of `vscode` is the VS Code extension or another app-server client, which cannot always be told from the desktop app. |
| Gotchas | The `model` column is mostly empty. The real model sits in rollout files, which HC2 does not read, so show "unknown". |
| Live state | No per thread. HC2 can say only that no Codex process exists at all (everything ended) or that one does (unknown). |
| Docs | https://developers.openai.com/codex (redirects to https://learn.chatgpt.com/docs) |
| Changelog | https://learn.chatgpt.com/docs/changelog and https://github.com/openai/codex/blob/main/CHANGELOG.md |
| llms.txt | https://developers.openai.com/codex/llms.txt (and `llms-full.txt`) |
| Confidence | High |

## pi

| Item | Detail |
|---|---|
| Install | `pi` on the path. |
| Version source | `~/.pi/agent/install/current-version`. Also `pi --version`. |
| Agent folder | `~/.pi/agent`, or the folder named by `PI_CODING_AGENT_DIR`. |
| Settings | `~/.pi/agent/settings.json` |
| Releases | `~/.pi/agent/install/releases/<version>` |
| Sessions | `~/.pi/agent/sessions/--<folder-with-dashes>--/<timestamp>_<uuid>.jsonl` |
| Session format | Documented and versioned JSONL (format 3, a tree linked by `id` and `parentId`). See `docs/session-format.md` in the pi repository. |
| Fields HC2 reads | The first line (`type` is `session`): `id`, `cwd`, `timestamp`, `version`. Later lines: the latest `session_info` entry's `name`, and the latest `model_change` entry's `provider` and `modelId`. |
| Live state | No. A running pi shows as a process called `pi`, but its working folder needs `lsof`, so HC2 cannot link a process to a session cheaply. |
| Gotchas | Session files are written lazily, so a fresh install has none. The parser follows the documentation and has not been checked against real files. The project moved: the old repository and the old npm scope are stale. |
| Docs | https://pi.dev/docs/latest (Markdown source in the repo under `packages/coding-agent/docs/`) |
| Changelog | https://github.com/earendil-works/pi/blob/main/packages/coding-agent/CHANGELOG.md |
| llms.txt | None. Use the repo's `docs/` folder. |
| Confidence | Medium |

## Hermes Agent

| Item | Detail |
|---|---|
| Install | `hermes` on the path, or `/Applications/Hermes.app`. |
| Version source | The first line of `hermes --version`. It is a script wrapper and takes about a second. |
| State folder | `~/.hermes` |
| Config | `~/.hermes/config.yaml` |
| Sessions | SQLite file `~/.hermes/state.db`, table `sessions`. Open it read-only. |
| Other | `~/.hermes/kanban.db` (not read). |
| Fields HC2 reads | `id`, `title` (falling back to `display_name`), `model`, `started_at`, `ended_at`, `cwd`, `archived`. |
| Live state | A session with no `ended_at` while a Hermes process exists is running. This is a hint, not proof. |
| Docs | https://hermes-agent.nousresearch.com/docs/ |
| Changelog | https://github.com/NousResearch/hermes-agent/releases |
| llms.txt | https://hermes-agent.nousresearch.com/docs/llms.txt |
| Confidence | Medium |

## Ollama

| Item | Detail |
|---|---|
| Install | `/Applications/Ollama.app` and the `ollama` command. |
| Version source | The app's `Info.plist`. The server's own version is available at `GET http://127.0.0.1:11434/api/version` while it runs. |
| Pulled models | Manifests under `~/.ollama/models/manifests`. No server needed. |
| Loaded models | `GET http://127.0.0.1:11434/api/ps`, which also gives model memory. Local call only. |
| App database | `~/Library/Application Support/Ollama/db.sqlite`, tables `chats` (`id`, `title`, `created_at`) and `messages` (for `model_name` and `updated_at`). Open it read-only. |
| Logs | `~/.ollama/logs/server.log` |
| Pid file | `~/Library/Application Support/Ollama/ollama.pid` |
| Live state | n/a. Report loaded models instead. |
| Docs | https://docs.ollama.com |
| Changelog | No docs changelog page. Use https://github.com/ollama/ollama/releases |
| llms.txt | https://docs.ollama.com/llms.txt (and `llms-full.txt`) |
| Confidence | Medium |

## LM Studio

| Item | Detail |
|---|---|
| Install | `/Applications/LM Studio.app`, and the `lms` command, often at `~/.lmstudio/bin/lms`. |
| Version source | The app's `Info.plist`. |
| Conversations | Upstream stores them at `~/.lmstudio/conversations/*.conversation.json`. Not yet checked on a real machine. |
| Loaded models | Through its local API when the server is running. |
| Docs | https://lmstudio.ai/docs |
| Changelog | https://lmstudio.ai/changelog |
| llms.txt | https://lmstudio.ai/llms.txt |
| Confidence | Low |

## Cursor IDE

| Item | Detail |
|---|---|
| Install | `/Applications/Cursor.app`, with a `cursor` command shim. |
| Version source | `Contents/Info.plist`. Also `cursor --version`. |
| User data | `~/Library/Application Support/Cursor/User` |
| Sessions | SQLite file `User/globalStorage/state.vscdb`. Table `cursorDiskKV`, rows whose key starts `composerData:`, hold a JSON value. Table `composerHeaders` adds the workspace id. Open it read-only. |
| Workspace map | `User/workspaceStorage/<workspaceId>/workspace.json`, whose `folder` is a `file://` URI. |
| Fields HC2 reads | From `composerData`: `name`, `createdAt`, `lastUpdatedAt`, `modelConfig.modelName`, `status`, `unifiedMode`. From `composerHeaders`: `composerId`, `workspaceId`, `createdAt`, `lastUpdatedAt`, `isArchived`. |
| Gotchas | The folder resolves only when the header's workspace id matches a workspace folder. Many ids belong to empty windows, so the folder is often missing. Some headers have no `composerData` body. |
| Live state | No per chat. HC2 can say only that Cursor is not running (everything ended) or that it is (unknown). |
| Docs | https://cursor.com/docs |
| Changelog | https://cursor.com/changelog |
| llms.txt | https://cursor.com/llms.txt |
| Confidence | Medium |

## Cursor Agent CLI

| Item | Detail |
|---|---|
| Install | `cursor-agent` (or `agent`) on the path. Usually a symlink into `~/.local/share/cursor-agent/versions/<version>`. |
| Version source | The real path of the symlink. |
| Config | `~/.cursor/cli-config.json` |
| Transcripts | `~/.cursor/projects/<folder-encoded>/agent-transcripts`. Content, so not read. They were empty in the spike. |
| Sessions | Not available. No session index was found. |
| Docs | https://cursor.com/docs/cli/overview |
| Changelog | https://cursor.com/changelog |
| llms.txt | https://cursor.com/llms.txt |
| Confidence | Low |

## Antigravity

| Item | Detail |
|---|---|
| Install | `/Applications/Antigravity.app` |
| Version source | `Contents/Info.plist`. |
| State folder | `~/.gemini/antigravity`. The `~/.gemini` folder may be shared with the Gemini CLI, so do not assume it belongs to one of them. |
| Conversations | `~/.gemini/antigravity/conversations/<uuid>.pb`. Opaque protobuf. Not decoded. |
| Summaries | `~/.gemini/antigravity/conversation_summaries.db` (not read). |
| Sessions | Not available. Report presence, version and resources only. |
| Docs | https://antigravity.google/docs |
| Changelog | https://antigravity.google/changelog |
| llms.txt | None found. |
| Confidence | Medium |

## Gemini app (macOS)

| Item | Detail |
|---|---|
| Install | `/Applications/Gemini.app` |
| Version source | `Contents/Info.plist`. |
| Sessions | Not available. Chat history is held in the cloud, and no local store was found. |
| Docs | https://gemini.google/ |
| Changelog | None found. |
| llms.txt | None found. |
| Confidence | Medium |

## Gemini CLI

| Item | Detail |
|---|---|
| Install | `gemini` on the path. Often installed through npm. |
| Version source | `gemini --version`. |
| State folder | `~/.gemini`. Upstream stores chats under `~/.gemini/tmp/<hash>/chats/*.json`. Not yet checked on a real machine. |
| Docs | https://geminicli.com/docs/ |
| Changelog | https://geminicli.com/docs/changelogs/ |
| llms.txt | https://geminicli.com/llms.txt (effectively the full docs). There is no separate `llms-full.txt`. |
| Confidence | Low |

## Windsurf and Aider

Probed in the spike. Not in the v1 coverage list.

| Harness | Install and version | Sessions | Docs | Changelog | llms.txt | Confidence |
|---|---|---|---|---|---|---|
| Windsurf | `/Applications/Windsurf.app`, version from `Info.plist`. The vendor's update feed now serves a different product build, so it is not a reliable app version. | Not confirmed. Expected state folder `~/.codeium/windsurf`. | https://docs.windsurf.com | https://windsurf.com/changelog | https://docs.windsurf.com/llms.txt | Low |
| Aider | `aider` on the path. Version from `aider --version`. | No index. Each repository gets its own `.aider.chat.history.md`, which is content and is not read. | https://aider.chat/docs/ | https://aider.chat/HISTORY.html | None | Low |

## Latest-version sources

Used in S7 (FR-7). All are plain GETs from allow-listed hosts. See the [research notes](../research/telemetry-and-tooling.md) for the full docs and version table, including npm and GitHub release endpoints.

| Harness | Machine-readable source |
|---|---|
| Claude Code | npm `@anthropic-ai/claude-code` (`latest` tag), or GitHub releases |
| Claude desktop | `https://downloads.claude.ai/releases/darwin/universal/RELEASES.json` (not documented as an API) |
| Codex CLI | npm `@openai/codex` (`latest` tag only), or GitHub releases |
| Codex desktop | The app's Sparkle appcast on `persistent.oaistatic.com` (not documented as an API) |
| Gemini CLI | npm `@google/gemini-cli` (`latest` tag) |
| pi | npm `@earendil-works/pi-coding-agent` (`latest` tag) |
| Cursor | The vendor's update API (not documented) |
| Ollama, Hermes | GitHub releases |
| LM Studio | The redirect at `https://lmstudio.ai/download/latest/...`, which carries the version in its target |
| Aider | PyPI package `aider-chat` |

Unauthenticated GitHub API calls are rate limited, so prefer npm and Atom feeds, and cache with ETags.
