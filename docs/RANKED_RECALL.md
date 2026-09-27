<!-- screenpipe — AI that knows everything you've seen, said, or heard -->
<!-- https://screenpipe.com -->

# Optional lexical relevance search

The existing MCP `search` tool accepts `mode: "relevance"`:

```json
{
  "name": "search",
  "arguments": {
    "query": "aurora safety deadline",
    "mode": "relevance",
    "kind": "note",
    "since": "-30",
    "limit": 5,
    "format": "structured"
  }
}
```

This selects authorized, currently visible record text using Unicode word
tokenization, a small English stopword list, prefix matching for query words
of at least three alphabetic characters (numbers match exactly), and BM25 over the authorized matching candidate
pool. Coverage and adjacent query-word order contribute to the score. Content
hashes break equal-score ties; ingestion order and recency are not tie-breakers.
Identical text can finally tie by record ID. The scheme is lexical: it neither
infers truth from conflicting records nor resolves arbitrary aliases/synonyms.

Result text remains untrusted evidence with the same stable references,
permission checks, corrections/retractions and read receipts as other retrieval.
Hidden, superseded and retracted records are excluded before corpus statistics
are computed. Only the JSON `text` field is ranked, not arbitrary capture or
control metadata. Tag, kind and date filters still narrow the authorized scope.

The structured response uses `order: "relevance"` and
`ranking: "bounded_lexical_bm25_v1"`. Output budgets and clipping still apply.
`has_more` means matches remain beyond the selected/output window; `next_cursor`
is null. Relevance search explicitly rejects chronological cursors. Refine the
query/filters or increase the limit to retrieve more. Omitting `mode` preserves
literal substring search and existing chronological pagination. `recent` stays
chronological and rejects relevance mode.

## Resource and privacy boundaries

- At most 4,096 UTF-8 query bytes and 32 distinct non-stopword query terms.
- At most 10,000 matching candidates, 32 MiB of their JSON payloads, and 250,000
  candidate tokens per call. Exceeding a bound returns an explicit error asking
  for narrower filters, never a silently partial ranking. Results cap at 200.
- Persistent indexed reads route query terms through existing encrypted gram
  postings. Prefix verification and scoring happen on the authorized node.
  Snapshot and streaming readers provide the same result contract. No plaintext
  index, model provider, embedding service, new runtime dependency or scheduler
  is added. Work is still proportional to candidate/filter selectivity; this is
  not a claim of production-scale latency on every corpus.
- Indexed failures are returned rather than retried through an expensive
  streaming query after a resource/permission refusal. Existing literal fallback
  behavior is unchanged.

The Rust entry points are `query::ranked::{look, look_snapshot, look_indexed}`.
They return the existing `Answer` type with selected records in reverse rank
order, matching the low-to-high convention consumed by structured MCP output.
Callers display `records.iter().rev()` for best first and retain `truncated`.
As with existing query APIs, the serving layer is responsible for appending
the supplied read receipt before releasing data.

## Evals

```sh
npm run eval:recall -- --gate=contracts
npm run eval:ranked -- --gate=contracts
npm run eval:ranked
cargo test --locked --bin hc context_tests
```

The original suite and baseline remain unchanged. The new suite retains the
seven original capability oracles, adds reversed-insertion variants, and tests
explicit lexical contracts and access/lifecycle boundaries. Some multi-record
cases explicitly accept any order, while a separate metamorphic check requires
the same ranking across insertion variants. This prevents an arbitrary order
from being scored as comprehension while still detecting unstable ties.

No-vocabulary-overlap paraphrases remain unmet and are reported as failures.
Query reformulation, semantic enrichment, answer synthesis and user-created
recurring tasks belong in the external harness; this endpoint executes none of
those responsibilities. No model trials are claimed by the deterministic evals.
