<!-- screenpipe — AI that knows everything you've seen, said, or heard -->
<!-- https://screenpipe.com -->

# Recall outcome evals

Finite pass/fail evals of HC retrieval. No performance leaderboard, latency
targets, model calls, agent runtime, scheduler, or background service. Every run
uses freshly generated identities and encrypted synthetic records in temporary
storage. It never opens the user's HC store or system keychain.

## Run

Requires the repository's Rust toolchain and Node 20 or later. No new dependencies.

```sh
# Validate cases and calibrate the evaluator; this does not evaluate HC.
npm run eval:recall:check

# Execute HC against every case, and fail if any intended outcome is unmet.
npm run eval:recall

# Execute the same cases, but gate only established contracts and infrastructure.
# Capability failures remain prominently reported; they are not converted to passes.
npm run eval:recall -- --gate=contracts
```

The default command is expected to exit 1 on the initial baseline: the default literal search does not
implement ranked or semantic recall. The opt-in lexical relevance mode has its
own suite described below. Exit 0 means the selected gate passed;
exit 1 means an evaluated outcome did not pass; exit 2 means the runner could
not complete. Per-case infrastructure errors are also explicit in reports and
fail either gate. A Rust collector test passing means evidence was collected,
not that recall succeeded. Do not cite its test count as the eval result.

Evidence, grader report, oracle-free collector input and provenance are saved
under ignored `target/recall-evals/<run-time>/`. Reports include suite, collector,
evaluator, core-input and evidence hashes, source commit, worktree status and
toolchain versions. Hashes bind artifacts; they do not authenticate a claimed
execution. Keep the complete evidence when comparing runs. `baseline.json`
records the first completed evaluation; do not overwrite it to hide regressions.

## What is evaluated

`cases.json` contains 26 synthetic scenarios:

- **19 existing contracts:** literal/case/Unicode recall, empty results, newest
  first presentation, bounded selection and continuation, tag/date filtering,
  managed corrections, old-wording suppression, retractions, private replacements,
  secret/tag grant boundaries, expiration, revocation, independent conflicting
  observations, reopen continuity, and stale-cache rejection.
- **7 desired capabilities:** relevant evidence ahead of newer incidental mentions
  (two cases), paraphrased workout/decision recall (two), an explicit person alias,
  commitment direction, and evidence spanning two constraints.

Every scenario executes the real scan, snapshot and encrypted-index read paths.
Core query results are presented newest first, matching MCP's
`structured_search_page`; there is no extra query expansion or relevance sorter
in the collector. Inputs are sent verbatim. Gold requires the right evidence in
the returned positions, not merely its existence somewhere in storage.

For every returned item, the collector also dereferences its actual source ID
and verifies the record hash and full original payload. The evaluator checks
the text and matching references. Explicitly inaccessible records must fail
point reads as well as disappear from search. This tests citation integrity,
not whether an LLM's answer is entailed by the cited evidence.

Stale-cache cases have distinct path expectations: the fresh scan must see the
correction, while stale snapshots/indexes must refuse to answer. They must not
fall back to old records. Restart continuity tests a reopened HC store, not
compaction or cross-session behavior of an agent.

The collector reads corpus/query input with the gold removed; the separate
Node evaluator owns the oracle. Grader calibration rejects wrong ordering,
missing or duplicated evidence, invented text, unverified citations, leaked point
reads, always-empty/always-deny behavior, invalid continuation, missing execution,
duplicate observations and mismatched suites. Calibration observations are
fabricated and are not counted as HC trials.

## Relevance retrieval

`npm run eval:ranked -- --gate=contracts` executes the separate
`ranked-cases.json` suite through all three real retrieval paths. It keeps the
seven original capability queries and oracles, adds reversed-insertion cases,
and checks explicit lexical contracts, stable ordering, metadata exclusion and
access/lifecycle boundaries. `npm run eval:ranked` gates all outcomes, including
the still-unmet capabilities. See [relevance search](../../docs/RANKED_RECALL.md)
for the API, resource limits and interpretation. The frozen literal suite and
first baseline are unchanged.

## Adjacent context contracts

Run the existing MCP context and capture-projection tests alongside these evals:

```sh
cargo test --locked --bin hc context_tests
cargo test --locked --test capture_projection
```

They cover JSON output budgets, source metadata, pagination without gaps,
untrusted-evidence labeling, permission checks on continuations and replicated
corrections/retractions. Those tests execute different boundaries from the
core collector; report them separately. A label saying "untrusted evidence"
does not prove an agent resists prompt injection. Neither test set proves
production replication freshness or phone delivery.

## External agent trials, when needed

Agent selection, answer synthesis, compaction recovery, automatic memory use and
scheduled maintenance remain in the user's Codex/Claude harness or another
external client. Nothing here installs hooks, starts agents, schedules work or
adds a loop to HC. A future trial runner should be a one-shot external process;
a user-created recurring Codex task can invoke it without HC owning that task.

For an actual agent trial:

1. Seed an isolated synthetic HC store through an external fixture adapter and
   give a fresh harness only the case's task and scoped HC tools. Withhold the
   gold, hidden corpus and evaluator source from that harness. The current Rust
   collector's temporary stores are deleted after collection; it is not an
   agent trial server.
2. Hold model, instructions, tools, context budget and environment constant for
   baseline/candidate comparisons. Permit neither direct fixture-file reads nor
   a broader grant as a shortcut.
3. Retain the actual tool trace and final answer. Grade correct use of current
   evidence, claim-level citation support, unauthorized disclosure, irrelevant
   memory and honest abstention. A searchable fact alone is not a successful
   agent outcome. Include quiet/no-change turns and conflicting claims.
4. Report model trials separately from these deterministic HC outcomes. Missing
   execution remains unknown. Do not fabricate an agent score from a core pass.

No agent trials are implemented or claimed by this suite.

## Mission fit

The eval runner, evidence collector and grader run only during development.
The opt-in lexical endpoint belongs in generic HC retrieval; it adds no runtime
dependency, model integration, storage protocol, authority rule or scope-eval
policy change.
context assembly and domain workflows stay outside the core. Capability cases
describe desired outcomes without prescribing an implementation or weakening
existing search contracts.
