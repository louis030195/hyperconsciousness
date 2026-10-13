<!-- screenpipe — AI that knows everything you've seen, said, or heard -->
<!-- https://screenpipe.com -->

# HC alpha.8: precise lexical recall and paired outcome evaluation

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
