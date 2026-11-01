# Repository health: research and design

Research and design, 31 Oct to 1 Nov 2026. Nothing is built yet. Requirement FR-18 in [requirements.md](../requirements.md) and [ADR 0002](../adr/0002-how-hc2-reads-repositories.md) record the decisions. The slices are in [slices.md](../slices.md).

This page describes the tool only. Following OS-3, it holds no one's repositories, results or settings: every example is made up.

## 1. Recommendation

**Build it as an optional HC2 rule pack: a GitHub collector plus a `repo_health` pack, off by default. Copy Soundcheck's model (tracks, levels, checks), not its software.**

Reason: HC2 already has the parts a scorecard needs: deterministic rules, findings with a severity and a fix, acknowledgements with an expiry (waivers), diffs between scans (trend), and a planned local dashboard. Soundcheck is closed source, has no public price and needs a running Backstage.

| Route | Cost | Maintenance | Verdict |
|---|---|---|---|
| Soundcheck | Annual bundle subscription, no public price, sales-led ([FAQ](https://backstage.spotify.com/faqs)) | Run Backstage (Node, PostgreSQL, auth) and keep a catalog entry in every repo | ⚪ Not realistic for an individual user |
| Tech Insights and its maturity plugin | Free, Apache-2.0 | The same Backstage instance and catalog | ⚪ The same infrastructure cost as Soundcheck |
| 👉 HC2 module | £0. A trial took about 14 GitHub REST calls per repository. The authenticated limit is [5,000 an hour](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) | One collector, one rule pack and one dashboard page, inside code that is already maintained. The main upkeep is GitHub changing API fields, which HC2's tolerant parsers (R-2) report as "unknown" instead of failing | 🟢 Recommended |
| Standalone script and page | £0 | A second engine for findings, waivers, history and pages. A hosted page would also need a stored token | ⚪ Rebuilds the same core |

## 2. Research

Pages read on 31 Oct 2026. Method note: some pages were read through a fetch tool that summarises, so wording is paraphrased unless quoted. A second, independent sub-agent re-checked 24 of the key claims against the same pages: 22 confirmed, and the other 2 have been reworded to match what the page says.

### Backstage and Soundcheck

| Tool | What it is | Licence and cost | Needs Backstage? | Levels | Source |
|---|---|---|---|---|---|
| Soundcheck | Spotify's Backstage plugin for "defining engineering standards and measuring how healthy your software components are". A track is a set of levels. A level is complete when its checks pass and every earlier level is complete. Certifications and medals record the outcome | Closed source; sold only in the Spotify plugins bundle as an annual subscription; licence key required; no public price | Yes: a backend and a frontend plugin in your own Backstage, or Spotify Portal (hosted) | Tracks, levels, certifications, bronze/silver/gold medals | [Soundcheck docs](https://backstage.spotify.com/docs/plugins/soundcheck/index.md), [tracks](https://backstage.spotify.com/docs/plugins/soundcheck/core-concepts/tracks.md), [FAQ](https://backstage.spotify.com/faqs), [set-up](https://backstage.spotify.com/docs/plugins/soundcheck/setup-and-installation) |
| Soundcheck checks | YAML rules: `factRef`, `path`, `operator`, `value`, combined with all/any/not. Facts come from collectors; the GitHub collector covers branch protection and rules, code scanning, Dependabot and secret scanning alerts, and repo details. New collectors are TypeScript modules | As above | Yes | n/a | [checks](https://backstage.spotify.com/docs/plugins/soundcheck/core-concepts/checks), [GitHub collector](https://backstage.spotify.com/docs/plugins/soundcheck/core-concepts/fact-collectors/3p-integrations/github.md) |
| Spotify Portal | The SaaS edition of Backstage, run by Spotify, with Soundcheck included | No public price; the pricing URL returns 404; "Free trials are not currently available through the AWS Marketplace listing" | It is Backstage | Through Soundcheck | [Portal on AWS](https://backstage.spotify.com/docs/portal/aws-marketplace.md), [Try Portal](https://backstage.spotify.com/try-portal) |
| Tech Insights | Open-source Backstage plugins: fact retrievers collect data per catalog entity, and a JSON rules engine checks it | Apache-2.0, free; you host Backstage. Version 1.5.0, published 8 Sep 2026 (`npm view`) | Yes | Through the separate maturity plugin: Stone, Bronze, Silver, Gold | [workspace](https://github.com/backstage/community-plugins/tree/main/workspaces/tech-insights), [backend README](https://github.com/backstage/community-plugins/blob/main/workspaces/tech-insights/plugins/tech-insights-backend/README.md), [maturity](https://github.com/backstage/community-plugins/tree/main/workspaces/tech-insights/plugins/tech-insights-maturity) |
| Backstage itself | Needs Node, Yarn, Docker and Git. The starting config keeps data in memory; the database guide sets up PostgreSQL so data persists. Components are registered through metadata YAML stored with the code | Apache-2.0 | n/a | n/a | [getting started](https://backstage.io/docs/getting-started/), [database](https://backstage.io/docs/getting-started/config/database/), [catalog](https://backstage.io/docs/features/software-catalog/) |
| Roadie (hosted Backstage) | Teams plan "$24 per dev/month" for 50 to 150 developers, "Existing subscribers only"; scorecards are a paid extra | Commercial | Hosted | Not stated | [pricing](https://roadie.io/pricing/) |

### Open tools and GitHub APIs

| Tool or API | What it gives | Free, and works on a personal account? | Maintained? | Fit | Source |
|---|---|---|---|---|---|
| OpenSSF Scorecard API | 0 to 10 per check across about 20 checks, plus an overall score. Results come from a weekly scan of a listed inventory (more than 1.3 million repos, added to by pull request) or from a repo's own Scorecard Action | Yes for public repos. The Action needs GitHub Advanced Security on private repos | v5.6.0, 12 Oct 2026 | 🟢 One Gold check | [README](https://github.com/ossf/scorecard/blob/main/README.md), [checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md), [inventory](https://github.com/ossf/scorecard-infra/blob/main/CONTRIBUTING.md), [API](https://api.scorecard.dev/swagger.json), [Action](https://github.com/ossf/scorecard-action/blob/main/README.md) |
| Community profile API | `health_percentage` and a `files` object (README, licence, code of conduct, contributing, issue and PR templates). "The repository cannot be a fork." No security-policy key | Yes | GitHub | 🟢 Docs track | [REST docs](https://docs.github.com/en/rest/metrics/community) |
| Repo settings endpoints | `security_and_analysis` (admin only), vulnerability alerts, code-scanning default setup, private vulnerability reporting, branch protection | Yes, as the owner. On a Free plan most return 403 or 404 for private repos | GitHub | 🟢 Security and Delivery tracks | [get a repository](https://docs.github.com/en/rest/repos/repos#get-a-repository), [branch protection](https://docs.github.com/en/rest/branches/branch-protection#get-branch-protection), [default setup](https://docs.github.com/en/rest/code-scanning/code-scanning#get-a-code-scanning-default-setup-configuration) |
| Rulesets | Enforcement, readable through `GET /repos/{o}/{r}/rules/branches/{b}` (active rules only). Free plan: public repos only. Organisation rulesets and custom properties are organisation-only | Public repos only on Free | GitHub | 🟢 Read them; don't build on organisation features | [rules API](https://docs.github.com/en/rest/repos/rules), [plans](https://github.com/github/docs/blob/main/data/reusables/gated-features/repo-rules.md), [about rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets) |
| GraphQL API | Batches licence, rulesets, branch protection, security policy, code of conduct and alerts setting across many repos at once. No fields for `security_and_analysis`, code-scanning setup or the community profile | Yes; 5,000 points an hour | GitHub | 🟢 Use it to cut the call count | [limits](https://docs.github.com/en/graphql/overview/rate-limits-and-query-limits-for-the-graphql-api) |
| REST limits | 5,000 requests an hour authenticated, 60 unauthenticated | n/a | GitHub | 🔵 One full run fits easily; unauthenticated doesn't | [limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) |
| App installations | Listing installed apps needs a GitHub App user token. Check runs show which apps ran on a commit instead | n/a | GitHub | 🟢 Detect apps through check runs | [installations](https://docs.github.com/en/rest/apps/installations), [check runs](https://docs.github.com/en/rest/checks/runs#list-check-runs-for-a-git-reference) |
| Default community files | A public `.github` repo under a personal account supplies CODE_OF_CONDUCT, CONTRIBUTING, SECURITY, SUPPORT, and issue and PR templates to repos that lack them. "You cannot create a default license file." Inherited files aren't in each repo's tree | Yes | GitHub | 🟢 Checks must count inherited files | [docs](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/creating-a-default-community-health-file) |
| repolinter | File and content rules over a checked-out repo | Yes | ⚪ Archived on 6 Feb 2026 | ⚪ Don't adopt. GitHub's own `.github` ruleset has 3 rules (MIT licence, README, CODEOWNERS) | [repo](https://github.com/todogroup/repolinter), [GitHub's ruleset](https://github.com/github/.github/blob/main/config/repolinter-ruleset.json) |
| OpenSSF Allstar | Policy enforcement app | The hosted app is retired; you run it yourself. Personal-account support not confirmed | v4.6, 31 Aug 2026 | ⚪ Enforces, doesn't score | [repo](https://github.com/ossf/allstar) |
| safe-settings | Settings as code | Needs an organisation `admin` repo | 3.0.0, 5 Oct 2026 | ⚪ Organisation-only | [repo](https://github.com/github-community-projects/safe-settings) |
| OSPS Baseline scanner | Scans a repo against the OpenSSF Baseline controls | Personal-account use not confirmed | v0.33.1, 26 Oct 2026 | 🔵 A possible later source of check ideas | [repo](https://github.com/ossf/pvtr-github-repo-scanner) |
| OpenSSF Best Practices badge | Badge level lookup by repo URL | Yes | Active | 🔵 Optional Gold check later | [API](https://github.com/ossf/best-practices-badge/blob/main/docs/api.md) |

### Commercial scorecards, for features only

| Product | Levels model | Custom rules | Waivers | History | Free tier | Source |
|---|---|---|---|---|---|---|
| Cortex | An entity reaches a level only after passing every rule in it and below; points are optional | CQL, or scorecards as YAML with `expression`, `weight`, `failureMessage`, `level` | Yes: approved, time-limited, audited | Trend graphs and a progress report | None stated ("Custom pricing") | [scorecards](https://docs.cortex.io/standardize/scorecards), [as code](https://docs.cortex.io/standardize/scorecards/scorecards-as-code.md), [exemptions](https://docs.cortex.io/standardize/scorecards/rule-exemptions.md), [pricing](https://www.cortex.io/pricing) |
| OpsLevel | Categories by levels (default Bronze, Silver, Gold); pass every check in a level to advance | jq success conditions, repo grep with regex and globs | Not found in the docs | Level trend and per-check burn-up | None listed; plans show "Get pricing" | [levels](https://docs.opslevel.com/docs/categories-and-levels), [checks](https://docs.opslevel.com/docs/getting-started-with-checks), [pricing](https://www.opslevel.com/pricing) |
| Port | Levels (Basic, Bronze, Silver, Gold); all rules at a level and below must pass; "% of rules passed" reported; no weights | JSON conditions on entity properties | Blog advice only | % passed over time; "result last change" per rule | Yes: "$0 (up to 15 seats)" | [concepts](https://docs.port.io/governance/standards-and-compliance/concepts-and-structure), [scorecards](https://docs.port.io/scorecards/concepts-and-structure/), [pricing](https://www.port.io/pricing) |

Features worth copying:
- Every check carries a fix message ([Cortex](https://docs.cortex.io/standardize/scorecards/evaluate.md)).
- Checks are defined as files in a repo ([Cortex](https://docs.cortex.io/standardize/scorecards/scorecards-as-code.md)).
- Waivers expire and keep a record ([Cortex](https://docs.cortex.io/standardize/scorecards/rule-exemptions.md)).
- A new check can be set to "Enable Later", so it doesn't drop every repo at once ([OpsLevel](https://docs.opslevel.com/docs/getting-started-with-checks)).
- Each rule result stores when it last changed ([Port](https://docs.port.io/scorecards/concepts-and-structure/)).

## 3. API behaviour that shaped the design

- **Missing Scorecard results.** The Scorecard API returns 404 for a repo that neither runs the Scorecard workflow nor appears in the weekly scan's [inventory](https://github.com/ossf/scorecard-infra/blob/main/CONTRIBUTING.md). The dashboard shows "Not published", not a failure.
- **The alerts endpoint mixes tools.** The code-scanning alerts query also returns Scorecard's own SARIF alerts, so the alerts check filters by tool.
- **Read the alert's message, not only its rule id.** A low Scorecard security-policy score can mean the policy file was found but has no linked content, such as an email address or web link, which Scorecard's docs weight at 6 of 10 points ([checks.md](https://github.com/ossf/scorecard/blob/main/docs/checks.md#security-policy)). The rule id alone doesn't say which part failed.
- **Apps are found through check runs.** Listing app installations needs a GitHub App user token. A `gh` token gets 403: "You must authenticate with an access token authorized to a GitHub App in order to list installations". Apps that post check runs can be detected from those check runs instead, with no extra access.
- **Rules over history need a start date.** PRs written before a description rule existed shouldn't count against it, so the rule counts only PRs merged on or after its `since` date.
- **Cost.** A trial by hand took about 14 REST calls and 5 seconds per repository, before GraphQL batching and caching.

## 4. Proposed checks

### Model

- **Tracks** group checks by topic: Docs, Security, Delivery, Maintenance and Custom.
- **Levels** are Bronze, Silver and Gold. A repo reaches a level when every applicable check at that level and below passes. This matches Soundcheck, Cortex, OpsLevel and Port.
- **Score** is the share of applicable checks that pass. Waived and not-applicable checks are left out of the count.
- **Every check is deterministic:** a GitHub REST field, a file in the default branch, or the Scorecard API. No LLM runs in a check.
- **Results** are pass, fail, waived (with a reason and an expiry), not applicable, or unknown (with a reason). An API error is always unknown, never a pass.
- **Alerts are read in full.** Any check that uses Scorecard or code-scanning alerts reads the alert's message (`most_recent_instance.message.text`), not only its rule id. The evidence column shows that message (section 3).
- **Applicability:**
  - Forks and archived repos are not scored.
  - Dormant repos (no push for 365 days) get only the Bronze docs checks plus "archive or revive".
  - Private repos on the Free plan can't use rulesets, branch protection, code-scanning default setup or private vulnerability reporting, and their `security_and_analysis` comes back empty. Those checks are marked not applicable there, not failed.
  - A repo can switch off checks that don't fit it (for example releases for a website), with a reason.

### Predefined checks

| Track | Level | Id | Passes when | Source |
|---|---|---|---|---|
| Docs | 🥉 | `docs.readme` | A README is at the root | Git tree of the default branch |
| Docs | 🥉 | `docs.licence` | A licence is detected (not `NOASSERTION`) | `GET /repos/{o}/{r}` → `license.spdx_id` |
| Docs | 🥉 | `docs.description` | The repo has a description | `GET /repos/{o}/{r}` |
| Docs | 🥈 | `docs.security_policy` | A security policy exists in the repo or is inherited from the owner's `.github` repo | GraphQL `isSecurityPolicyEnabled`; git tree as a fallback |
| Docs | 🥈 | `docs.contributing` | CONTRIBUTING exists, in the repo or inherited | Community profile, which counts inherited files |
| Docs | 🥈 | `docs.pr_template` | A PR template exists, in the repo or inherited | Community profile |
| Docs | 🥇 | `docs.code_of_conduct` | A code of conduct exists | Community profile |
| Docs | 🥇 | `docs.issue_templates` | Issue templates exist | Community profile |
| Docs | 🥇 | `docs.topics` | At least one topic | `GET /repos/{o}/{r}` → `topics` |
| Security | 🥉 | `sec.secret_scanning` | Secret scanning is on | `security_and_analysis.secret_scanning` |
| Security | 🥉 | `sec.push_protection` | Push protection is on | `security_and_analysis.secret_scanning_push_protection` |
| Security | 🥉 | `sec.dependabot_alerts` | Dependabot alerts are on | `GET /repos/{o}/{r}/vulnerability-alerts` → 204 |
| Security | 🥈 | `sec.dependabot_security_updates` | Automatic security updates are on | `security_and_analysis.dependabot_security_updates` |
| Security | 🥈 | `sec.dependabot_version_updates` | `.github/dependabot.yml` exists | Git tree |
| Security | 🥈 | `sec.codeql` | CodeQL default setup is configured, or a CodeQL workflow's latest run on main succeeded | `GET /repos/{o}/{r}/code-scanning/default-setup`; workflow runs |
| Security | 🥈 | `sec.private_vuln_reporting` | Private vulnerability reporting is on | `GET /repos/{o}/{r}/private-vulnerability-reporting` |
| Security | 🥇 | `sec.scorecard_score` | A Scorecard result exists, is at most 7 days old and scores 7.0 or more | `GET https://api.scorecard.dev/projects/github.com/{o}/{r}` |
| Security | 🥇 | `sec.no_high_alerts` | No open Dependabot or CodeQL alert of high or critical security severity (Scorecard's own alerts left out) | `GET .../dependabot/alerts`, `GET .../code-scanning/alerts` |
| Delivery | 🥉 | `del.ci_present` | At least one workflow file | Git tree, `.github/workflows/` |
| Delivery | 🥉 | `del.ci_green` | The latest run on main of every workflow file succeeded or was skipped. Dependabot's own runs are ignored | `GET .../actions/runs?branch=main` |
| Delivery | 🥈 | `del.branch_protected` | Main is protected against deletion and force pushes, by a ruleset or classic protection | `GET .../rules/branches/main`; `GET .../branches/main/protection` |
| Delivery | 🥈 | `del.pr_required` | Changes to main need a PR | Rule type `pull_request` |
| Delivery | 🥈 | `del.status_checks_required` | Required status checks are set | Rule type `required_status_checks` |
| Delivery | 🥇 | `del.code_scanning_gate` | Code scanning results gate merges | Rule type `code_scanning` |
| Delivery | 🥇 | `del.recent_release` | A release in the last 180 days, unless the repo opts out | `GET .../releases` |
| Maintenance | 🥉 | `mnt.active_or_archived` | A push in the last 365 days, or the repo is archived | `GET /repos/{o}/{r}` → `pushed_at`, `archived` |
| Maintenance | 🥈 | `mnt.no_stale_prs` | No open PR older than 30 days | `GET .../pulls?state=open` |
| Maintenance | 🥇 | `mnt.dependabot_prs_fresh` | No open Dependabot PR older than 14 days | `GET .../pulls?state=open`, author `dependabot[bot]` |

### Custom checks

HC2 ships no custom checks. Each user adds their own in their own config, using the kinds under "Adding more checks".

Repos with no merged PRs yet get "unknown" for the check-run and PR-rule checks, not a fail.

How the `pr_rule` kind counts:

- **Merged PRs decide the result.** Only PRs merged on or after the rule's `since` date count, up to the last `max_prs`. With fewer than `min_prs`, the check shows unknown, for example "unknown (2 of 3 needed)": info only, never counted in the level. Otherwise the `min_share` applies to those PRs.
- **Open PRs are info only.** Open PRs created on or after the `since` date are checked too. The evidence column shows the open and merged counts apart. Open PRs never decide pass or fail, because a description can still change until the PR is merged.
- **Bot PRs are left out.** A PR whose author type is `Bot`, such as one from `dependabot[bot]`, is skipped. A bot that runs with a person's token shows as a `User` and still counts [inference].

### Local clones

A read-only local collector adds a Local track for the clones on the user's machine. It has its own column and doesn't count towards the level, because it describes the machine, not the repo.

- **Discovery:** configured roots, plus the folders HC2 already records for sessions (FR-2). Worktrees are grouped under their repo, and each clone is joined to its GitHub row by its remote URL.
- **Confidential folders (P-2):** skipped entirely. HC2 runs no git command in them and shows "Confidential A: skipped". Masking the output isn't enough, because `git status` would still read file names.

| Id | Flags | Source |
|---|---|---|
| `loc.uncommitted` | Uncommitted changes (count only) | `git status --porcelain=v2` |
| `loc.unpushed` | Commits not on the upstream branch | `git rev-list --count @{u}..HEAD` |
| `loc.no_remote` | No GitHub remote, so no copy off the machine | `git remote get-url origin` |
| `loc.stale_worktrees` | A worktree whose folder is gone, or whose branch is merged | `git worktree list --porcelain` |
| `loc.stash` | Stash entries. Every worktree shares one stash | `git stash list` |
| `loc.tracks_main` | A feature branch whose upstream is `origin/main`, so a bare push goes to main | `git for-each-ref` |
| `loc.hook_missing` | The repo ships a hook installer (such as `scripts/install-hooks.sh`) or a pre-commit config, but the hook isn't installed | File checks, plus the repo's own hook setting, never HC2's `/dev/null` override below |
| `loc.ignored_secrets` | `.env`-style files that git doesn't ignore. Names only, never contents | `git check-ignore` |

Every git call is on a fixed allow-list of reading commands (the ones above, plus `git config --get`), has a timeout, and never fetches, pulls or writes. Each call also carries these settings, checked against git's manual on 31 Oct 2026:

| Setting | What it stops | Source |
|---|---|---|
| `--no-optional-locks` and `GIT_OPTIONAL_LOCKS=0` | `git status` rewriting the index as a side effect | [git](https://git-scm.com/docs/git), [git-status](https://git-scm.com/docs/git-status) |
| `-c core.fsmonitor=false` | An fsmonitor hook command, which `core.fsmonitor` can name | [git-config](https://git-scm.com/docs/git-config) |
| `-c core.hooksPath=/dev/null` | Every hook. git-config says this setting will "disable all hooks entirely" | [git-config](https://git-scm.com/docs/git-config) |
| `--no-pager` and `GIT_PAGER=cat` | A pager. The manual gives the `cat` rule for `GIT_PAGER`, not for `core.pager` | [git](https://git-scm.com/docs/git) |
| `GIT_TERMINAL_PROMPT=0` | Terminal prompts, for example for HTTP authentication | [git](https://git-scm.com/docs/git) |
| No diff or log commands on the allow-list | textconv, which runs "only git diff and the git log family", and `diff.external`, which replaces git's own diff. `-c diff.external=` is added as well, but the manual doesn't say an empty value switches it off, so the allow-list is the real control | [gitattributes](https://git-scm.com/docs/gitattributes), [git-config](https://git-scm.com/docs/git-config) |

### Adding more checks

- Checks are data, not code: a `[[repo_checks]]` table in the user's own `config.toml`, so a user can add a check without a release.
- Each entry has an `id`, `title`, `track`, `level`, `kind`, the kind's parameters, a `fix` and a docs link.
- The kinds are a fixed list, each backed by tested code in the pack:

  | Kind | Example (made-up values) |
  |---|---|
  | `file_exists` | `paths = ["SECURITY.md", ".github/SECURITY.md"]`, counting inherited files |
  | `workflow_present` | A workflow that uses `ossf/scorecard-action` |
  | `app_installed` | `slug = "example-app"`, read from check runs |
  | `setting_equals` | `field = "security_and_analysis.secret_scanning_push_protection.status"`, `value = "enabled"` |
  | `pr_rule` | `max_words = 400`, `must_match = ["^## Testing"]`, `since = "2026-01-01"`, `min_share = 0.9`, `min_prs = 3`, `max_prs = 20`, `open_prs = "info"`, `skip_bots = true` |

- The predefined checks ship as defaults in the same format.
- A check that needs a new kind is a code change, with golden tests.
- `enforce_from = "YYYY-MM-DD"`: until that date a new check shows as info only, so adding a check never drops every repo at once.
- Waivers reuse HC2 acknowledgements: per repo and check, with a note and an expiry.

## 5. Dashboard sketch

### Overview: one row per repo

| Column | Content and states |
|---|---|
| Repo | Name, linked to `https://github.com/<owner>/<repo>`. Private repos show as "Private repo 1", "Private repo 2" and so on, with a 🔒 icon and the word, unless the user opts in to names |
| Class | Active · Dormant · Archived ⚪ · Fork ⚪ |
| Level | 🥇 Gold · 🥈 Silver · 🥉 Bronze · ❌ None, always with the word |
| Score | Percentage, plus a ▲ or ▼ change since the last scan |
| Docs, Security, Delivery, Maintenance, Custom | Passed out of applicable per track, for example "7/9" |
| CI on main | ✅ Green · ❌ Failing (linked to the run) · ➖ None |
| Local | ✅ Clean · counts such as "2 unpushed" or "1 stale worktree" · ➖ No clone · 🔒 Confidential: skipped |
| Scorecard | Score and date, or "Not published" |
| Failing | Count, then the three most severe check names, each linked to the GitHub page that fixes it, for example `/settings/security_analysis` |
| Waived | Count, with the soonest expiry |
| Checked | Time of the last successful collection, or ❔ with the reason it failed |

- Sorted by level, then score, lowest first, so the work rises to the top.
- Filters: class (dormant, forks and archived hidden by default), track, level.
- Summary strip: repos per level, and checks that changed state since the last scan.
- Status is never shown by colour alone, so every state has an icon and a word (X-2).

### Repo detail: one row per check

| Column | Content |
|---|---|
| Check | Title and id |
| Track and level | For example "Security · 🥈" |
| Result | ✅ Pass · ❌ Fail · ⏸ Waived until a date · ➖ Not applicable · ❔ Unknown |
| Evidence | The field or file and its value, for example `secret_scanning_push_protection: disabled` |
| Fix | One sentence and a link |
| Last change | When the result last changed |

### Where it lives

| Option | Verdict |
|---|---|
| 👉 A "Repositories" section in HC2's local web dashboard, separate from the harness pages, plus `hc2 repos` and `hc2 repos --json` | 🟢 Recommended. Local only, matching S-1. Private repos are counted but not named unless the user opts in |
| A standalone local HTML file | ⚪ Interim only, if the dashboard (S4) is a long way off |
| A public static page published from a repo | ⚪ Not now. It would publish security gaps, needs a stored token for settings endpoints, and would have to leave private repos out |

## 6. How it fits HC2

| HC2 part | Repo health use |
|---|---|
| Rule packs (pure functions, findings out) | `rules/repo_health`: one finding per failing check. Rule id `repo.<check>`; stable id from the rule and repo name |
| Severity | Failing Bronze Security check: red. Other Bronze or Silver: amber. Gold: info |
| Acknowledgements with expiry | Waivers |
| Diff since the last scan, history | Trend and "last change" |
| Opt-in network allow-list | `api.github.com` and `api.scorecard.dev`, the documented Scorecard API host |
| MCP read tools | A `repo_health` read tool, so an LLM can triage and propose fixes |
| Proposals and passkey approval | Later: catalogued fix actions such as switching on push protection. Each one changes a repo, so it needs approval |
| Off by default (like FR-17) | The pack is for people who own repositories, so it stays opt-in |

Design constraints:
- **Scope.** It fits, because HC2's subject is the health of the AI-assisted set-up and the repos are where the harnesses work. Off by default, with a separate "Repositories" section on the dashboard.
- **Results stay local.** Results live in the user's state folder and reach only local surfaces and the MCP read tool. Nothing is published. HC2 only reads repositories: a later fix action changes a repo only through a proposal a person approves (FR-10).
- **Auth through `gh`,** with the same discipline as `hc2.collect.run_command`:
  - a fixed allow-list: only `gh api` with an explicit `--method GET`, plus `gh api graphql` for queries only (a document with a mutation is refused);
  - never `gh auth token`, `gh auth status --show-token` or any command that prints a credential;
  - a timeout on every call, and output parsed as JSON only.
- **Fallback token.** An environment variable named in the config. The token is sent only to `api.github.com` and never logged or stored.
- **Speed (F-1).** The collector has its own schedule and a cache, outside the 5-second scan. Two ways to cut the call count:
  - one GraphQL query for most per-repo facts;
  - conditional requests with ETags: a `304` reply to an authenticated conditional request "does not count against your primary rate limit" ([GitHub docs](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api#use-conditional-requests)).
- **Privacy.** PR bodies are read only to count words and match patterns, then dropped (P-1). Repo names, descriptions and PR text are untrusted data (S-4). The dashboard names only public repos. Private repos are counted, and named only if the user opts in.

## 7. Delivery plan

The slices R0 to R4, with their "done when" tests, are in [slices.md](../slices.md#optional-lane-repository-health-fr-18).

Later, not now:
- Catalogued fix actions behind passkey approval (needs S6).

## 8. Not checked

- That the community profile counts inherited files was observed on another account's public repo. GitHub's docs don't say so.
- Whether `isSecurityPolicyEnabled` counts an inherited `SECURITY.md` is not confirmed.
- Whether a workflow-based CodeQL set-up shows in the default-setup endpoint is not confirmed. The `sec.codeql` check covers both routes for that reason.
- Whether a repo that starts publishing Scorecard results appears in the API straight away was not tested.
- Whether Scorecard counts a `SECURITY.md` inherited from the owner's `.github` repo was not tested.
- Which hooks `git status` can trigger: the githooks page doesn't attribute any hook to the commands on the local allow-list. `post-index-change` runs when the index is written, which `--no-optional-locks` should prevent [inference], and `core.hooksPath=/dev/null` turns hooks off anyway.
- Shared workflows: GitHub's docs confirm that a public repo can call a reusable workflow stored in a public repo. Whether private repos on the Free plan can call one wasn't checked.
