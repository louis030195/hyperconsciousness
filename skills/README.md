# HC ingestion skills

These skills teach an agent to import selected records using its existing source
access and an authorized HC writer. They include source-specific selection,
provenance, incremental updates, privacy boundaries and readback checks.
Installing them does not connect accounts, grant access or start collectors.

## Install

Clone the public repository, then copy the instructions into one harness:

```sh
git clone https://github.com/louis030195/hyperconsciousness.git
cd hyperconsciousness
python3 scripts/install-ingestion-skills.py --dest ~/.codex/skills
```

For Claude Code, use `--dest ~/.claude/skills`. Other harnesses can use their own
skill directory. The installer requires Python 3.9+ and only copies Markdown,
YAML and JSON instructions. It does not install HC itself. Start a new agent
session if the harness discovers skills only at startup.

To select skills, repeat `--skill`; the shared `hc-ingest` dependency is included:

```sh
python3 scripts/install-ingestion-skills.py --dest ~/.codex/skills \
  --skill hc-ingest-codex --skill hc-ingest-claude
```

Use `--list` to list names or `--dry-run` with a destination to preview. Repeating
an identical install preserves files. A different existing skill or symlink is
left untouched and causes an error before any selected skill is installed.
Review local changes before replacing an older copy; there is no force option.

You can also copy selected skill folders manually. Include `hc-ingest` beside
every source skill so its relative reference links resolve. These source skills
ship in Git, independently of CLI releases and automatic binary updates.

## Choose a source

| Skill | Source-specific guidance |
| --- | --- |
| [hc-ingest](hc-ingest/SKILL.md) | Shared write, retry, freshness and verification contract |
| [hc-ingest-codex](hc-ingest-codex/SKILL.md) | Selected Codex chats and local session transcripts |
| [hc-ingest-claude](hc-ingest-claude/SKILL.md) | Claude Code sessions and Claude conversation exports |
| [hc-ingest-slack](hc-ingest-slack/SKILL.md) | Channel messages, threads, edits and coverage |
| [hc-ingest-google-workspace](hc-ingest-google-workspace/SKILL.md) | Gmail, Drive, Docs, Calendar and available Meet artifacts |
| [hc-ingest-github](hc-ingest-github/SKILL.md) | Issues, PRs, reviews, releases and workflow evidence |
| [hc-ingest-crm](hc-ingest-crm/SKILL.md) | Attio and HubSpot records and relationships |
| [hc-ingest-support](hc-ingest-support/SKILL.md) | Intercom, Zendesk and Discord support records |
| [hc-ingest-docs-tasks](hc-ingest-docs-tasks/SKILL.md) | Notion, Linear and Markdown knowledge exports |
| [hc-ingest-meetings](hc-ingest-meetings/SKILL.md) | Zoom, Cal.com, meeting notes and transcripts |
| [hc-ingest-analytics](hc-ingest-analytics/SKILL.md) | PostHog, GA4 and selected database aggregates |
| [hc-ingest-ads](hc-ingest-ads/SKILL.md) | Google Ads and Meta Ads measurement contracts |
| [hc-ingest-billing](hc-ingest-billing/SKILL.md) | Stripe billing records and aggregate reports |
| [hc-ingest-marketing](hc-ingest-marketing/SKILL.md) | Buffer, HeyReach and Loops content/delivery evidence |
| [hc-ingest-infra](hc-ingest-infra/SKILL.md) | AWS, Google Cloud, Cloudflare, Vercel and Sentry summaries |

Example request after installation:

> Use $hc-ingest-codex to import the selected project's chats from last week into
> my personal HC. Keep visible user and assistant turns, exclude tool output,
> show a small preview, then import and verify the selected records.

Or:

> Use $hc-ingest-ads to import this account's daily campaign totals for last
> month into our approved marketing destination. Preserve currency, attribution,
> reporting period and freshness, and verify an imported row.

An agent still needs usable provider access and an HC write grant. A company
connection that only exposes search/record tools cannot ingest data. The agent
should report the missing capability rather than use another account or copy
personal records into a company store. Provider API versions, scopes and local
chat formats must be checked in the target environment.

## Validation

Run `python3 -m unittest discover -s skills/tests` for installer behavior and
installed reference checks. [Review cases](tests/REVIEW.md) cover ingestion
decisions and nearby tasks. These checks do not demonstrate live provider
enrollment, continuous synchronization or successful agent imports.
