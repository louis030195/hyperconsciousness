<!-- screenpipe — AI that knows everything you've seen, said, or heard -->
<!-- https://screenpipe.com -->

# HC alpha.7: skill discovery and search excerpts

`hc find --scope skills` now matches multiword capability requests against skill
names and descriptions. Exact names rank first. Discovery includes Codex system
skills and cached plugin skills, with additional roots available through
`HC_SKILL_ROOTS`. A deeply nested directory no longer stops the remaining scan.

Compact MCP search results now show context around the matching passage, so a
match near the end of a long record can appear in the excerpt. Stable references,
clipping indicators and full point reads remain available for verification.

Ranked recall keeps query-specific scoring statistics, reducing token storage
and allowing several long records to share a query budget. The limits are
250,000 non-stopword tokens per document and 4,000,000 across matching candidates;
the existing candidate and payload limits still apply. Resource exhaustion
returns `query_limit_exceeded` without releasing a partial ranking.

Brief log-lock and capture-projection conflicts join the bounded MCP read retry
policy. Every retry reopens authorization and the read view. Revocations,
permission refusals, writes and reads carrying a one-use approval are not
replayed. Sustained ingestion contention can still return a retryable error.

This release also includes the earlier main-branch work on authenticated shared
loopback MCP connections, search-cache repair during ingestion, incremental file
readback, recall guidance and portable ingestion skills.

Search remains lexical. It does not resolve arbitrary aliases or paraphrases,
verify a retrieved claim, or make records outside a grant visible.

Run `hc update` to install, or use the native installer:

```sh
curl -fsSL https://raw.githubusercontent.com/louis030195/hyperconsciousness/main/install.sh | sh
```

Native archives and updater binaries are published for Mac ARM64/Intel, Linux
ARM64/x86-64 and Windows x86-64. Linux requires Ubuntu 24.04-compatible libraries;
Mac binaries are not notarized. HC remains a developer alpha.
