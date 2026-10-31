# Security policy

## Reporting a vulnerability

Please report security problems **privately**, using GitHub's private vulnerability reporting: [report a vulnerability](https://github.com/dao-wolf/ai-hc2/security/advisories/new).

If that link doesn't work for you:

1. Open this repository on GitHub.
2. Go to the **Security** tab.
3. Choose **Report a vulnerability** and fill in the form.

Do not open a public issue, pull request or discussion for a vulnerability.

Please include:

- what you found and why it matters;
- steps to reproduce it, using made-up data only;
- the version or commit you tested, and your OS.

Never include real session titles, paths, tokens or conversation content in a report.

## What to expect

This is a small, pre-alpha project run by volunteers. We aim to acknowledge a report within 7 days and to tell you what we plan to do within 30 days. We will credit you in the fix unless you prefer not to be named.

## Supported versions

Only the latest commit on `main` is supported while the project is pre-alpha.

## What counts

HC2 is built to run locally and to read metadata only. Examples of in-scope problems:

- a way for a web page, another user or a remote host to reach HC2's local API;
- a way for an LLM client to approve or run an action;
- confidential folder names, session titles or secrets appearing in output, logs or exports;
- an action acting on the wrong process;
- a weakness in the CI workflows or the release process.

The [threat model](docs/threat-model.md) lists what HC2 defends against and what it does not.
