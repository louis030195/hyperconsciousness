# Health evidence queries

The granted MCP reader exposes `health_status`, `health_summary`, and
`health_samples`. They read structured `health` / `health_sync` payloads on notes
with the `health` tag. Generic text search continues to use ingestion time.
These tools select by measurement time and preserve ingestion timestamps in
provenance. They never request broader permissions.

Example `tools/call` arguments:

```json
{"name":"health_summary","arguments":{"start":"2026-01-05","end":"2026-01-12","timezone":"America/Los_Angeles","metrics":["hrv_sdnn","hrv_rmssd","resting_heart_rate","steps","sleep"],"baseline_days":7}}
```

`end` is exclusive. Windows and baselines are bounded to 93 days. A zero-day
baseline disables comparison. `health_status` accepts optional `metrics` and
`source`; it returns available ranges and the last phone checkpoint.
`health_samples` accepts the same window plus `limit` (1–200) and `cursor`.
Rows are complete JSON objects. Changed evidence invalidates continuation;
restart the query instead of combining incompatible pages.

## Calculations and coverage

- HRV SDNN and RMSSD are distinct metrics in milliseconds. They are never pooled.
- Sources are separate. Apple and Oura steps must not be added together.
- Resting heart rate is separate from overnight mean/minimum heart rate.
- Missing observations are unknown. A recent sample does not prove complete sync.
- Means are sample means, not time-weighted estimates. Period means give equal
  weight to observed completed calendar days and report missing days.
- Sleep intervals are unioned within source and split at local midnight, with
  overlaps and unclassified in-bed time exposed. This is a calendar-day view,
  not a clinical sleep score or sleep-session average. Stage overlaps can make
  summed stage durations exceed the asleep union; use the asleep union.
- Immutable UUID deletion tombstones win over delayed uploads. For nondeleted
  stable IDs, the latest ingested observation wins. Re-created objects need new
  UUIDs. Cross-source samples are not silently deduplicated by numeric value.
- Current days are partial. Summary values are not diagnoses or causal claims.

## Storage and authorization

The v8 search index gains versioned AEAD-encrypted typed sidecars per authenticated
segment. No plaintext medical database or index migration is introduced. The
first health query builds missing sidecars; subsequent reads reuse them. Authenticated per-shard metric headers let narrow queries skip unrelated
medical payloads while always retaining deletion and checkpoint evidence. Changed
segments and key views invalidate the corresponding projection. All returned
rows are filtered by the current grant chain and capture visibility; grants,
revocations and log tails are rechecked before response. Raw evidence remains
in the encrypted log and is addressable by returned references.

Queries are bounded to two million projected rows, 64 MB per encrypted shard,
and 64 KB returned JSON. Large summaries must use fewer metrics or a shorter
window. Sync status is omitted from sample pages to keep pagination useful.
