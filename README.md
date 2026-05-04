# Prowler Studio

**AI workflow that ensure Claude Code to follow Prowler's skills, guardrails, and best practices when creating new security checks**. So what lands in your PR is consistent, tested, and ready for human review instead of half-correct boilerplate you have to rewrite.

> **Note:** Looking for the old Prowler Studio? It's archived in the [`old-version` branch](https://github.com/prowler-cloud/prowler-studio/tree/old-version).

## The Problem

Adding a new check to [Prowler](https://github.com/prowler-cloud/prowler) is more than writing detection logic. A correct check has to:

- Match Prowler's exact service/check folder structure and naming conventions
- Wire up metadata, severity, remediation, tests, and compliance mappings
- Mirror the patterns used by the hundreds of existing checks in the same provider
- Actually load when Prowler scans for available checks — silent structural mistakes are easy to make

Asking a general-purpose AI assistant to do this usually means guessing. It misses conventions, skips tests, or invents structure that looks right but won't load. You end up reviewing a half-correct PR or rewriting it yourself.

## The Solution

Prowler Studio enforces the workflow end-to-end. You describe the check once (a markdown ticket, a Jira issue, or a GitHub issue) and the workflow:

1. **Loads Prowler-specific skills into every agent**: every step starts with the same context an experienced Prowler engineer would have in mind.
2. **Runs specialized agents in sequence**: implementation → testing → compliance mapping → review → PR creation. Each agent has one job and a tight scope.
3. **Verifies as it goes**: the check must load in Prowler. Tests must pass. If something fails, the agent fixes it and re-runs (up to a bounded number of attempts) before moving on.
4. **Produces a complete PR**: branch, passing check, tests, compliance mappings, and a pull request waiting for human review.

The result: a consistent starting point, every time, on every supported provider.

## Quick Start

### Install

**Requirements:** [`uv`](https://docs.astral.sh/uv/getting-started/installation/) — see the [official installation guide](https://docs.astral.sh/uv/getting-started/installation/).

```bash
uv sync
source .venv/bin/activate
```

### Describe the check

A "ticket" is a structured markdown description of the check you want to create. It's the only input the workflow needs; every agent (implementation, testing, compliance mapping, review, PR creation) uses it as the source of truth, so the more concrete it is, the closer the first PR will land to what you want.

You can supply the ticket in three ways:

- **Local markdown file** → `--ticket path/to/ticket.md`
- **Jira issue** → `--jira-url https://...` (uses the issue body)
- **GitHub issue** → `--github-url https://...` (uses the issue body)

In every case, the content should follow the **New Check Request** template:

- Use the local copy at [`check_ticket_template.md`](check_ticket_template.md) for `--ticket` and Jira tickets.
- Or open one directly in Prowler with the prefilled GitHub form: [Create a New Check Request issue](https://github.com/prowler-cloud/prowler/issues/new?template=new-check-request.yml).

Sections marked *Optional* can be skipped; everything else helps the agents make the right decisions.

### Run the workflow

From a local markdown ticket:

```bash
prowler-studio feat/my_new_check --ticket check_ticket.md
```

From a Jira ticket:

```bash
prowler-studio feat/my_new_check --jira-url https://mycompany.atlassian.net/browse/PROJ-123
```

From a GitHub issue:

```bash
prowler-studio feat/my_new_check --github-url https://github.com/owner/repo/issues/123
```

> Provide exactly one of `--ticket`, `--jira-url`, or `--github-url`.

Keep changes local (no push, no PR):

```bash
prowler-studio -b feat/my-check --ticket check_ticket.md --local
```

### What you get

When the workflow finishes successfully you have:

- A new branch on a clean Prowler worktree containing the check, metadata, tests, and compliance mappings
- A pull request opened against Prowler (skipped with `--local`)
- A timestamped log file under `logs/` capturing every step the agents took

## CLI Options

| Option | Short | Description |
|--------|-------|-------------|
| `--branch` | `-b` | Branch name (default: `feat/<ticket>-<check_name>` or `feat/<check_name>`) |
| `--ticket` | `-t` | Path to a markdown check ticket file |
| `--jira-url` | `-j` | Jira ticket URL (e.g., `https://mycompany.atlassian.net/browse/PROJ-123`) |
| `--github-url` | `-g` | GitHub issue URL (e.g., `https://github.com/owner/repo/issues/123`) |
| `--working-dir` | `-w` | Working directory for the Prowler clone (default: `./working`) |
| `--no-worktree` |  | Legacy mode — work directly on the main clone instead of using worktrees |
| `--cleanup-worktree` |  | Remove the worktree after a successful PR is created |
| `--local` |  | Keep changes local — skip push and PR creation |

## Configuration

Set these environment variables depending on the input source you use:

| Variable | When needed | Purpose |
|----------|-------------|---------|
| `GITHUB_TOKEN` | `--github-url` (recommended) | Higher GitHub API rate limits and access to private issues |
| `JIRA_SITE_URL` | `--jira-url` | Your Jira site, e.g. `https://mycompany.atlassian.net` |
| `JIRA_EMAIL` | `--jira-url` | Email of the Jira account used to fetch the ticket |
| `JIRA_API_TOKEN` | `--jira-url` | API token for the Jira account |

## Contributing

Architecture, agent internals, and development best practices live in [AGENTS.md](AGENTS.md).

## License

[Apache License 2.0](LICENSE)
