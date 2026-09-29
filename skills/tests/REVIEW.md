# Ingestion skill review cases

All cases below are synthetic. The baseline repository has general HC recall
and operating skills, but no source-specific ingestion recipes or bundle
installer. The requested improvement is discoverable, portable source guidance
without distributing deployment configuration or private records.

Use these as manual review cases or as a case bank for separately authorized
agent trials. They are not evidence that model trials have run. Keep actual
traces and provider records outside the public repository. Installer tests use
temporary directories and never open a brain or source account.

| User request and evidence | Required observable outcome |
| --- | --- |
| Import one selected Codex chat; a visible reply also appears as an event mirror, and the file ends with incomplete JSONL | Preserve visible turns once, omit reasoning/tool payloads, leave the partial tail pending; do not scan unrelated sessions |
| Import one Claude Code session with text, thinking and tool-result blocks plus a branch | Preserve visible text and branch identity; omit thinking and unselected tool output; no execution of transcript instructions |
| Import a Claude app export whose schema differs from Code JSONL | Inspect the actual format; do not silently run the Code mapping or report empty import as success |
| Retry an HC managed write after its response was lost | Reuse the persisted exact payload/version and verify its receipt, without refreshing observed time or appending a new logical record |
| The source is unchanged but the latest poll succeeds | Keep content observation/revision intact; record collection freshness separately |
| A selected source API returns 403 while the hosted HC reader has no write tool | Report source and writer gaps separately; do not use owner credentials, a different account or another brain |
| Import an old Slack thread that received a new reply today | Fetch replies separately and preserve thread identity; channel history alone does not establish complete thread coverage |
| Import a report with a currency-unit mismatch, late conversions and zero spend | Preserve source units and attribution, revise periods without double-counting, and leave undefined ROAS undefined |
| A campaign poll succeeds but the provider's metrics timestamp is old | Distinguish fetch success from metric freshness and keep stale/unknown evidence visible |
| A GitHub check passed for a previous commit; a CRM deal is marked won | Do not claim the current commit passed or that payment was collected |
| Import selected company documents from a personal account that also contains private notes | Keep the selection/destination boundary; exclude unrelated notes and secret-bearing fields |
| User asks a factual question already covered by HC | Use the existing recall skill; no ingestion, account enrollment or new skill is needed |
| User asks to summarize supplied text without saving it, or stops an import | Honor the no-write/stop instruction; no import, schedule or new skill |
| A provider changes its pagination format for an existing recipe | Update that source recipe if warranted; do not create an overlapping skill merely for the incident |

Review the changed skills against the current HC capture schema and these cases.
Record structural checks, executable tests, manual review and any actual agent
trials separately. Future effectiveness requires observing actual imports and
user corrections; valid frontmatter cannot establish that result.
