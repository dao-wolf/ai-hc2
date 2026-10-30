# AI HC2 local API (schema 2)

Version 0.1, 30 Oct 2026. Draft, built from the Mac app's needs. It covers requirements FR-14, A-1 to A-4 and S-7.

## Basics

- **Address.** The socket binds to 127.0.0.1, and pages are served as `http://localhost:<port>`, because passkeys need a domain name. The Host check accepts `localhost:<port>`. The S6 spike will confirm whether `127.0.0.1:<port>` must also be accepted. On start it writes `~/.local/state/ai-hc2/api.json`, readable only by the user: `{url, pid, started, schema: 2}`. Clients use that file to find the server.
- **Auth.** Every request carries the token from `~/.local/state/ai-hc2/token`. The token allows reading and proposing only.
- **Approver actions** (approve, reject, acknowledge, change config) also need a passkey check. See "Approvals" below.
- **Headers.** Native clients send the token as `Authorization: Bearer <token>`. The web UI keeps it in an HttpOnly, SameSite=Strict cookie. It never goes in a URL.
- **Origin rule.** A request is allowed when it has no Origin header, or its Origin equals the server's own. Anything else is refused, and the Host header must match. No CORS.
- **Content.** Every text field is redacted in the core before it is sent. Confidential folders always appear as "Confidential A", "Confidential B" and so on.

## GET /api/v2/status

Used by the menu bar. The target size is under 8 KB.

| Field | Content |
|---|---|
| `schema`, `generated`, `scan_id`, `scan_seconds` | `generated` is ISO 8601 with an offset. |
| `scan_state` | `ok`, `running`, `failed` or `stale`. |
| `scan_error` | `{kind, hint}`. Plain English, no paths, and it says why: for example "macOS may be waiting for you to allow folder access". |
| `next_scan_at` | When the next scan is due. |
| `level` | `red`, `amber`, `green` or `unknown`. |
| `counts` | `{red, amber, info, acknowledged}` |
| `top` | Up to 10 findings. Each is `{id, sev, title, fix, harness, ack?, web_path}`. Titles and fixes are 200 characters at most. |
| `changes` | `{since, fixed_count, new_count, fixed[≤4], new[≤4]}` |
| `approvals` | `{pending_count, oldest_at, top[≤3]: {id, title, action_kind, risk}}` |
| `harnesses` | `[{id, name, state, sessions_running, sessions_stale}]` |
| `pressure` | `{level, mem_used_pct, swap_gb, load1}` |
| `content_hash` | A hash of the content with all times left out. Clients use it to tell whether anything really changed. |

## GET /api/v2/events

Server-sent events: `status.changed`, `scan.failed`, `approval.created`, `approval.decided` and `action.result`. If the stream drops, clients poll `/status` every 60 seconds.

## GET /api/v2/proposals?state=pending

Each proposal:

| Field | Content |
|---|---|
| `id`, `created_at`, `expires_at` | |
| `source` | `{type: rule, llm or person, client, model}` |
| `action` | `{kind, label}` |
| `target` | A redacted summary, for example "dev server on port 8777, node, started 3 h ago". |
| `preview` | `{summary, details[≤10]}` |
| `risk` | `low`, `medium` or `high` |
| `reversible` | true or false |
| `reason`, `finding_id`, `notes_count`, `web_path` | |
| `preview_hash` | sha256 of the canonical action, its parameters and the preview. |

## Approvals

1. **Start.** A client calls `POST /api/v2/approvals/challenge` with `decisions: [{id, preview_hash, decision: approve or reject, reason?}]`. The response is `{challenge_id, challenge, expires_at}`. The challenge binds every decision, a nonce, an expiry and the current audit chain head. It can be used once only and expires within minutes.
2. **The person passes a passkey check** (user verification, for example Touch ID) on the web approve page. The CLI and the Mac app open this page; they never approve on their own.
3. **The decision.** `POST /api/v2/approvals` sends `{challenge_id, assertion, decisions}`, with the same decisions as step 1. One touch covers the whole batch.

The response has a result for each id: `{id, status, trace_id?}`.

| Status | Meaning |
|---|---|
| `ok` | Decided. |
| `forbidden` | No valid passkey check. |
| `conflict` | The preview changed, or the proposal was already decided. |
| `expired` | The challenge or the proposal expired. |

- **Repeats.** Sending the same `challenge_id` again returns the first results, so a double click is safe.
- **Execution.** The executor re-verifies the stored assertion just before running.
- **Acknowledgements and config changes.** They use the same challenge and decision flow, with decision kinds `acknowledge` and `config_change`.
- **Links.** `aihc2://proposal/<id>` only opens the proposal. No link ever approves, rejects or changes a setting.

## Passkeys

| Endpoint | Purpose | Needs |
|---|---|---|
| `POST /api/v2/passkeys/register/options`, then `POST /api/v2/passkeys/register` | Add a passkey | The first passkey: no check (trusted on first use, in `hc2 setup`). Later passkeys: an assertion from an existing passkey. |
| `GET /api/v2/passkeys` | List passkeys: id, name, created, last used | The token |
| `DELETE /api/v2/passkeys/{id}` | Remove a passkey | An assertion from a different passkey, or the last one's own assertion |

Any change to the passkey list raises a finding on every surface. It can't be acknowledged for 7 days, and it's written into the hash-chained audit log.

## The widget

The widget never calls the API. The Mac app writes `widget.json` (about 2 KB): level, counts, scan state, top 6 `{sev, title}`, the changes counts, and pending approvals. The app reloads the widget only when `content_hash` changes, and then:

- at least 60 seconds after the last change;
- at most once every 5 minutes;
- at most about 30 times a day.
