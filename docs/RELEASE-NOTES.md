<!-- screenpipe — AI that knows everything you've seen, said, or heard -->
<!-- https://screenpipe.com -->

# HC alpha.14: keep reads usable during ordinary appends

Indexed reads now validate their pinned search prefix when another writer
appends while permissions are being prepared. Literal search, relevance search,
record reads and overview can return that prefix after a bounded tail check.
The response excludes records appended after the pinned heads.

Current permissions are still required. Capture corrections, relevant grant
revocations, changed prefixes and unreadable or over-budget tails refuse the
response. Entry and release both check the tail. Resource limits and retry
budgets are unchanged.

This fixes a reproduced read conflict. Search relevance and contention from
other causes still have limitations.

Install with `hc update`. HC remains a developer alpha.

## Earlier alpha.13: recover safely from stale permission snapshots

Indexed reads now prepare the search index before refreshing their permission
snapshot. A snapshot invalidated by a concurrent append reports a transient read
conflict and can use the existing bounded retry policy. Each attempt checks fresh
authorization. Actual revocations, expired grants and integrity failures still
refuse access; writes and one-time approved reads are not replayed.

This release also includes the main-branch optional trusted query-node adapter.
An explicitly configured reader can serve existing HC search and MCP calls
without a local replica. Installed skill and PKM discovery remain local. The
adapter respects the endpoint's advertised search schema, refuses redirects and
does not silently fall back to another store. See [query-node setup](QUERY-NODES.md)
for credential, timeout and offline limitations.

These changes do not establish improved semantic recall or eliminate contention
on a busy store. The existing three-attempt, 250 ms retry-start budget is unchanged.

Install with `hc update`. HC remains a developer alpha.

## Earlier alpha.12: preserve complete search evidence

Search now returns the whole compacted note whenever it fits the excerpt budget,
even when the query matches near the end. This preserves earlier qualifications
such as draft status. Longer evidence still uses explicitly clipped passages,
and point reads retain the original content and formatting.

The offline outcome scorer verifies contiguous middle excerpts, rejects oversized
normalized responses and requires reviewer attribution. Scores record hashes of
the scorer and reviewed report. Clipped passages cannot satisfy complete-source
or full-point-read requirements. These are retrieval and grader corrections;
they do not establish improved agent answering or semantic recall.

Install with `hc update`. HC remains a developer alpha.

## Earlier alpha.8 through alpha.11 changes

Relevance search accepts `match_terms: "all"` to require every non-stopword query
term in the same record. An entity-plus-fact lookup can avoid exhausting the
candidate budget on unrelated records that match only the common term. The
indexed path intersects required-term postings and verifies the full conjunction
under the original grant. Default `any` and literal searches are unchanged.
Invalid combinations fail explicitly. Matching oversized records still fail
without returning a partial ranking. This is lexical matching, not semantic
retrieval; facts spread across records need separate queries or broader discovery.

Writer guards now explicitly unlock on drop. An unrelated child process briefly
inheriting a file descriptor can no longer prolong the writer lock after its
owner finishes. The single-writer exclusion remains enforced while a guard lives.

The external evaluation tools now compare frozen, paired baseline/candidate
outcomes with a complete planned denominator and family-cluster confidence
intervals. Missing evidence, boundary violations, critical regressions and
insufficient independent families block a quality-gain claim. Synthetic grader
tests cannot pass as actual agent evidence. The analysis is manual and offline;
it adds no runtime model, collector or CI job.

This release also includes the main-branch encrypted search-index reuse and local
discovery improvements since alpha.7. Permissions, encryption and existing
chronological search behavior remain unchanged. Current-value and raw-provider
questions still require appropriately fresh, sufficiently detailed evidence.

Install with `hc update`. Native builds cover Mac ARM64/Intel, Linux ARM64/x86-64
and Windows x86-64. Linux requires Ubuntu 24.04-compatible libraries. Mac binaries
are not notarized. HC remains a developer alpha.
