<!-- screenpipe — AI that knows everything you've seen, said, or heard -->

# HC scalability and privacy improvements

All 27 isolated synthetic scenarios completed successfully. No live HC store or private chats were used. The durable record, grant, encryption and replication protocols stay intact; the rebuildable search cache moves to format v7.

## Measured retrieval changes

| Fixture / query | Before ms | After ms | Ratio |
| --- | --- | --- | --- |
| records-100k / common_broad | 4,054.83 | 2.38 | 1,707.06× |
| records-100k / short_broad | 4,071.89 | 2.01 | 2,027.37× |
| records-100k / rare_broad | 163.34 | 28.22 | 5.79× |
| records-100k / absent_broad | 38.66 | 0.40 | 96.93× |
| records-100k / rare_denied | 157.62 | 0.42 | 377.95× |
| records-1m / rare_broad | 1,641.95 | 33.77 | 48.63× |
| records-1m / absent_broad | 384.61 | 3.04 | 126.64× |
| diverse-4k / absent_broad | 233.65 | 0.32 | 736.68× |
| diverse-32k / absent_broad | 874.70 | 1.04 | 838.83× |
| managed-10k / absent_broad | 30.33 | 21.67 | 1.40× |
| authors-128 / absent_broad | 42.22 | 30.08 | 1.40× |

The 100k common/short queries decrypt 21 candidate bodies to return 20 results, versus 100,000 before. The 1m rare query also decrypts 21 instead of 1,004. Result bodies are still reopened and signature checked; short strings, Unicode, scoped denials, corrections and pagination retain exact matching semantics.

## Storage and build tradeoffs

| Records | Build before / after s | Index before / after MB |
| --- | --- | --- |
| records-10k | 1.38 / 1.94 | 1.65 / 1.65 |
| records-100k | 12.04 / 10.10 | 16.49 / 16.56 |
| records-1m | 101.57 / 106.06 | 165.85 / 166.53 |

Adaptive filters spend additional encrypted directory space to avoid saturated routes. At 5k diverse 32k-byte records, physical index size changed from 100.43 MB to 105.83 MB. Build times vary on the shared desktop; this is not a claim that every operation improves. Rebuilding old derived caches is required once; signed history is untouched.

## Active writes

| Fixture | Before reads | After reads | Before writes | After writes |
| --- | --- | --- | --- | --- |
| records-100k | 0/8 | 8/8 | 17 | 4 |
| writer-fallback | 0/8 | 8/8 | 35 | 5 |

Both use eight attempts and a nominal 100 ms writer interval plus append time. Faster queries shorten the trial, so fewer writes land; this is not an equal-duration load test or production availability measurement. Deterministic regression tests also inject ordinary appends, retractions and revocations during reads, including a revocation appended during tail validation itself.

## Sync and IAM

| Records / authors / page KiB | Initial before / after ms | Idle before / after ms | 250-record delta before / after ms |
| --- | --- | --- | --- |
| 1,000 / 1 / 1024 | 27.67 / 27.44 | 0.27 / 0.31 | 11.07 / 11.31 |
| 10,000 / 1 / 1024 | 280.40 / 275.75 | 2.09 / 2.18 | 20.63 / 18.57 |
| 50,000 / 1 / 1024 | 1,749.81 / 1,843.63 | 10.63 / 13.45 | 61.81 / 63.60 |
| 10,000 / 1 / 64 | 868.40 / 849.62 | 2.21 / 1.99 | 32.64 / 28.82 |
| 10,000 / 16 / 1024 | 297.40 / 296.24 | 3.08 / 2.64 | 13.42 / 13.61 |

Sync pages seek the relevant segment instead of decoding all earlier records. Head discovery still scans history. Incoming signature, predecessor, replay, fork and removed-device-cutoff validation remain unchanged. These are two local stores without network transport or gateway authorization.

| Grants + same number revocations | Disk reopen before / after ms | Resident exact lookup before / after ms |
| --- | --- | --- |
| 100 | 3.40 / 3.16 | 0.0019 / 0.0014 |
| 10000 | 251.32 / 252.99 | 0.0336 / 0.0013 |

MCP now reuses a verified in-process permission fold and advances signed tails under the same usable-key fingerprint. The table's disk reopening benchmark intentionally still decodes disk caches; it does not measure that MCP reuse. Pointer reuse, stale-key rejection and newly appended revocation are covered by regression tests. Grant-prefix lookup inspects at most two sorted matches after seeking the range.

## Privacy, control and bounds

- Agent responses omit hidden-record counts and the global device inventory. New durable read receipts retain principal, grant, returned count, truncation and query hash; historical receipts remain append-only.
- Reads pin data history while release checks validate new signed tails, relevant ancestor revocations and any managed-capture change. MCP reopens the key view and checks expiry. Company reads recheck current policy and membership without consuming a proof twice.
- Managed capture projections reuse ordinary/audit tails; corrections, exact retries, conflicts and inaccessible retractions retain their original semantics. Resident retention has a 50,000-record and conservative 16 MiB accounting budget. Oversized projections still require transient work proportional to managed history.
- Encrypted directory roots reference up to 128 independently authenticated 1 MiB pages. A regression exercises a directory larger than the former 16 MiB flat cap and recovery from a missing page. The total decoded directory still has a 128 MiB cap and lives in memory; shard storage grows with history. Two generations are retained.
- `HC_RESIDENT_CACHE=off` disables between-call snapshot/search/policy retention. It trades latency for lower memory retention, while keeping encrypted disk indexes and authorization. Missing means enabled; only `on`, `1`, `true` explicitly enable it. Invalid configured values disable it.
- Tail catch-up stops after three passes, 10,000 records or 64 MiB and fails closed. Small snapshot/streaming reads retain conservative freshness checks. Very busy control streams and independently refreshed/cleaned caches can still force retry.
- Existing bounded durable capture batching and streaming blob deduplication were retained and remeasured. No background sync, deployment, new service, permission broadening or new runtime dependency was introduced.

## Method, evidence and limits

Baseline: `4ed790416bf503b695a5103f6862c1e543e7f5e2`. Same Apple M5 Max, Rust 1.88.0 release profile, synthetic workload parameters and nice 10. Scenarios ran sequentially, separate from test/build processes; OS caches were warm on a shared desktop. Seven query samples, three at 1m records. Ratios are medians, not production p95/p99 guarantees. <=10k scenarios compare indexed output with the streaming oracle; larger fixtures verify known corpus counts and result compliance rather than exhaustive recall.

The full run's binary/source hashes, raw samples, resource measurements and receipts are in the companion artifact. Final verification also covers owner cache controls and multiple processes refreshing the index. Runtime caches, metadata isolation and the trusted gateway are still security boundaries: encrypted storage cannot hide plaintext from an authorized recipient or a compromised key-holding process. Use independently keyed stores, OS identities and workload limits per trust domain. WAN, authenticated service throughput, mobile memory, SSO and multi-tenant isolation were not benchmarked.

Reproduce with `cargo build --release --examples`, then `python3 examples/run_dimensions.py --output /new/results --temp /empty/fixtures`. `--case records-100k` selects a case. The runner creates synthetic child stores and refuses a nonempty fixture directory. This is a POSIX benchmark runner; Rust correctness CI targets Linux, macOS and Windows.

## Final verification

The full benchmark run preceded final concurrency/publication and CLI audit hardening. The final source replayed `records-100k`, `authors-128` and `managed-10k` successfully: common-query median 2.55 ms, short-query 2.18 ms, rare-query 28.87 ms at 100k, with 8/8 writer-test reads successful. Exact binary and source hashes distinguish the runs in the companion artifact.

The 10-read audit loop, including index reopening and a durable receipt after every query, changed from 221.54 ms to 103.13 ms median. It excludes transport and response formatting. The much smaller query-only timings above must not be presented as full API latency.

Local validation: 541 Rust tests passed across the debug/release suites plus the final CLI regression, with four existing ignored tests. All-target lint passed in debug and release. Formatting, diff whitespace, 21 scope-evaluator tests and all 24 structural scope cases passed. npm metadata and archive checks passed. Windows `x86_64-pc-windows-msvc` release cross-compilation with `blake3/pure` passed; this is not native Windows execution. The new CLI regression confirms no result text is released when the durable audit append is locked.

Mission review: changes remain in encrypted storage, bounded retrieval, verified replication, grants, owner controls and their tests. No runtime dependency, new library module, hosted provider or agent planner was added. Scope tests provide structural evidence, not an independent security audit. The remaining linear sync-head/import work, transient large managed folds and trusted-process boundary remain explicit limitations.
