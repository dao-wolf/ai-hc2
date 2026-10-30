# Claude adapters

What the three Claude adapters read, where it comes from and how far to trust it. This is the detail behind the Claude sections of [sources.md](sources.md). Code: `src/hc2/adapters/claude_code.py`, `claude_desktop.py`, `claude_cowork.py`, with shared helpers in `claude_common.py`.

## Checked against

| Item | Value |
|---|---|
| Claude Code CLI | 2.1.314 (also seen: sessions written by 2.1.30x to 2.1.31x) |
| Claude desktop app | 4.29.0 |
| Date | 30 Oct 2026 |
| Docs fingerprint | Not recorded yet. S7 adds it (M-3). |

## Adapters

| Adapter id | Harness | Reads |
|---|---|---|
| `claude-code-cli` | Claude Code command line | `~/.claude`, the `claude` symlink |
| `claude-desktop-code` | Claude desktop, Code tab | The app, its embedded Claude Code copies, the Code tab session index, and the live registry |
| `claude-desktop-cowork` | Claude desktop, Cowork | The app and the Cowork session index |

## How trust is shown

Each session carries `field_sources`: one entry per field that has a value, saying where it came from.

| Reliability | Meaning here |
|---|---|
| High | Read straight from a named field that the harness writes every time. |
| Medium | Worked out from more than one source, or from a value that is true only at the moment of the scan (such as running state). |
| Low | A fallback or a guess, such as the file's modification time standing in for a missing timestamp. |

## Privacy rules every adapter follows (P-1 to P-3)

- Only the named fields below are taken. Every other value is dropped in memory. Message text is never kept, logged or returned, and a test plants sentinel strings in message text and checks they never reach `to_json()`.
- Reads are bounded. A transcript is read at its first 64 KiB and last 256 KiB only. A line over 256 KiB is skipped without parsing. Index files over 4 MiB and registry files over 64 KiB are not parsed.
- The model name comes only from `message.model` of an assistant record. Titles come only from the three title record types. Text inside a message that looks like a title record or a folder is ignored, because only top-level keys of a whole line are used.
- A session is marked `confidential` when its folder is, or is inside, one of `ctx.confidential_folders`. The folder is returned as a raw path, because the core redacts it later. The adapter drops the title of a confidential session, so a title cannot leak if a later stage forgets to mask it.
- For CLI sessions, a project folder name in `~/.claude/projects` that starts like the encoded name of a confidential folder also counts. Claude builds that name by turning every symbol in the working folder into a dash. This catches a transcript with no readable `cwd`. It can mark a sibling folder with a similar name too, which is the safe way to be wrong.
- Problems are plain sentences with counts and no paths, file names or ids.
- Nothing is written, no binary is run, and there is no network use. The only child process is one `ps` call with a 2 second timeout.

## Claude Code CLI (`claude-code-cli`)

### Install

| Field | Source | Confidence |
|---|---|---|
| Location | The first `claude` found in `~/.local/bin`, `/usr/local/bin` or `/opt/homebrew/bin` | High |
| Version | Folder name at the end of the symlink's target (`.../versions/<version>`) | High for the usual install. Missing for a non-versioned target, which raises a problem. |

### Sessions

Transcripts are `~/.claude/projects/<folder>/<sessionId>.jsonl`.

| Session field | Source | Confidence |
|---|---|---|
| `id` | The transcript file name | High |
| `created` | `timestamp` of the first record that has one, in the head window | High |
| `last_activity` | `timestamp` of the last record that has one, in the tail window. Falls back to the file's modification time. | High, or Low for the fallback |
| `folder` | `cwd` of the first record that has one, in the head window. Falls back to the registry's `cwd`. | High, or Medium for the fallback |
| `title` | The latest `customTitle` (record type `custom-title`), else `agentName` (`agent-name`), else `aiTitle` (`ai-title`). Falls back to the registry's `name`. | High, or Medium for the fallback |
| `model` | `message.model` of the last assistant record in the tail window. Names starting with `<` (such as a placeholder) are skipped. | Medium. It is the last model used, not necessarily the current one. |
| `origin` | `entrypoint`: `cli` is CLI, names containing `vscode`, `jetbrains` or `ide` are IDE, `claude-desktop` is desktop, anything else is unknown | High |
| `state` | See the table below | Medium |

Other keys read: `type` of each record, to find title and assistant records.

### Running state

The registry is `~/.claude/sessions/<pid>.json`. A file counts only if all of these hold.

1. `pid` is a whole number above 1 and `os.kill(pid, 0)` finds the process.
2. `ps` reports the executable's name as `claude`.
3. When the file has `procStart`, it equals the process start time from `ps`. This rejects a reused process id.

| Registry `status` | State |
|---|---|
| `busy` | running-busy |
| `idle` | running-idle |
| `waiting` | waiting |
| Anything else, on a live process | unknown |
| No live registry entry | ended |
| The process table could not be read | unknown (never ended), with a problem |

For a session found running through the registry, HC2 also records `pid` (the registry's `pid`, confirmed alive by the checks above) and `state_since` (the registry's `statusUpdatedAt`, when the status last changed). Both are `null` when the session is not running or the registry has no usable value. HC2 uses them to link a session to its process tree and to work out how long it has been in its current state.

A registry entry with no transcript yet is listed from the registry alone: `sessionId`, `name`, `cwd`, `entrypoint`, `startedAt` and `updatedAt`.

### Sessions left to the desktop adapter

A transcript is not listed here when its `entrypoint` is `claude-desktop`, or when its id is a `cliSessionId` or `priorCliSessionIds` entry in the Code tab or Cowork index. The desktop adapters list them once. Desktop transcripts with no matching index entry (for example after the session was deleted in the app) are therefore not listed anywhere.

## Claude desktop, Code tab (`claude-desktop-code`)

### Installs

| Install | Source | Confidence |
|---|---|---|
| App | `Claude.app/Contents/Info.plist`, key `CFBundleShortVersionString`, in `/Applications` or `~/Applications` | High |
| Embedded Claude Code | Folder name in `~/Library/Application Support/Claude/claude-code/<version>/<hash>/claude.app`. One entry per version. | High |

### Sessions

Index files are `~/Library/Application Support/Claude/claude-code-sessions/<account>/<organisation>/local_<uuid>.json`.

| Session field | Source | Confidence |
|---|---|---|
| `id` | `sessionId` | High |
| `title` | `title` | High |
| `folder` | `cwd` (may be a work tree) | High |
| `model` | `model` | High |
| `created`, `last_activity` | `createdAt`, `lastActivityAt` (milliseconds since the epoch) | High |
| `origin` | Always desktop | High |
| `state` | `cliSessionId` looked up in the live registry (same rules as the CLI). No live entry means ended, and so does `isArchived`. | Medium |

Also read: `originCwd`, used only to decide whether the session is confidential, and `cliSessionId`. `priorCliSessionIds` is read only by the CLI adapter, to avoid listing a session twice.

## Claude desktop, Cowork (`claude-desktop-cowork`)

Install: the same app bundle and version as the Code tab. Index files are `.../Claude/local-agent-mode-sessions/<account>/<organisation>/local_<uuid>.json`.

| Session field | Source | Confidence |
|---|---|---|
| `id` | `sessionId` | High |
| `title` | `title` | High |
| `folder` | First entry of `userSelectedFolders`. The `cwd` key is a path inside the virtual machine and is never used. | High |
| `model` | `model` | High |
| `created`, `last_activity` | `createdAt`, `lastActivityAt` | High |
| `origin` | Always desktop | High |
| `state` | `isArchived` gives ended. Otherwise unknown, because Cowork has no per-session process. | Medium |

A Cowork session is confidential if any entry of `userSelectedFolders` is in a confidential folder. The adapter does not read `sessionType`, `processName`, `error` or any prompt, summary or account field.

## Problems the adapters can raise

Each sentence starts with the adapter's name and carries a count where it makes sense. None contains a path.

| Problem | When |
|---|---|
| Session folder not found | The app or CLI is installed but its session folder is missing |
| Session folder could not be read | Permission denied on the folder |
| Files could not be read | Permission denied or another read error on individual files |
| Files could not be read as valid data | Damaged, empty, too deeply nested or not JSON |
| Files not in a format this version understands | Valid JSON of the wrong shape, no `sessionId`, or over the size limit. The adapter may need an update (R-2). |
| Running-session list unreadable or odd | The registry folder cannot be read, or a registry file has no usable `pid` and `sessionId` |
| Could not check which Claude processes are running | The `ps` call failed or timed out. States become unknown. |
| App version could not be read | Missing or damaged `Info.plist` |
| Claude Code version could not be worked out | The symlink target has no version in its name |
| The scan failed unexpectedly | Anything else. Partial results are not kept in this case. |

## Format risks

These formats are not public interfaces. Expect change, and check them first when a scan reports problems.

- **Registry keys** (`procStart`, `status`, `pid`) are what make the running check reliable. If `procStart` disappears the check still works but cannot reject a reused process id, so it falls back to the process name alone.
- **`ps` output** is read with a fixed pattern for `lstart`. A different locale is avoided by running `ps` with `LC_ALL=C`. A future `ps` that changes the column layout would turn every session's state to ended or unknown.
- **Title record names** (`custom-title`, `agent-name`, `ai-title`) and their keys. A rename would leave sessions untitled rather than break anything.
- **`entrypoint` values** (`cli`, `claude-desktop`, `claude-vscode`) decide the origin and which adapter lists a session. A new value shows as unknown origin.
- **`cliSessionId` and `priorCliSessionIds`** decide the split between CLI and desktop. If they change, sessions could be listed twice.
- **Index files are large** (up to about 1.2 MB each, 350 or more of them, around 200 MB in all on a busy machine). Each is parsed once per scan and cached by size and modification time, which keeps a scan near one second. A much bigger store would need a cheaper reader.
- **Model name** is the last assistant record in the tail window. A session whose last 256 KiB holds no assistant record has no model.
- **Head window.** If the first record that holds `cwd` is larger than 64 KiB, the folder falls back to the registry (running sessions only) or stays empty. The project folder name check still covers confidentiality.
