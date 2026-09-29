# Record and receipt contract

Inspect the connected HC server's `tools/list` before using this example. It
describes the repository's versioned text-capture API. A reader-only deployment
may not expose it. Do not send unsupported fields or silently fall back to a
broader writer. The full protocol is documented in the repository's
[capture contract](https://github.com/louis030195/hyperconsciousness/blob/main/docs/CAPTURE-CONTEXT.md).

## One managed record

Synthetic `remember` arguments:

```json
{
  "text": "Source: example workspace, message 42\nSource updated: 2026-01-01T09:00:00Z\nObserved: 2026-01-01T10:00:00Z\nEvidence: The pilot will test offline search.\nCoverage: selected message body only; attachments excluded.",
  "kind": "note",
  "sensitivity": "personal",
  "tags": ["source:example", "import:pilot"],
  "context": {
    "version": 1,
    "producer": "example-importer",
    "source_id": "example-workspace",
    "record_id": "message:42",
    "revision": "source-revision-1",
    "observed_at_ms": 1767261600000,
    "material": "observation",
    "source_refs": []
  },
  "change": {"version": 1, "operation": "upsert"},
  "return_receipts": true
}
```

Choose the sensitivity allowed by the actual destination and grant. Lowering it
to make a denied write pass changes the disclosure scope and is not a repair.
Use `derived` for a summary and `task_handoff` for a continuation note. Store the
original source URL in the text or normalized body. `context.source_refs` accepts
only actual HC `author:sequence` refs, not external URLs or provider IDs.

The identity labels `producer`, `source_id`, `record_id` and `revision` must be
nonempty, at most 256 UTF-8 bytes and free of control characters. Context accepts
only the fields shown above; its serialized size is bounded at 8192 bytes. Extra
provider metadata belongs in `text`, not arbitrary keys inside `context`.

`context.version` is the envelope schema. `change.version` is a positive integer
that increases for each accepted content change or retraction. The provider's
revision is a separate opaque string. An exact same-version retry reuses its
receipt; changing any caller-controlled field, including observation time,
under that version conflicts. Preserve pending payloads through restarts.

`remember_many` takes `items` containing the record arguments above without
per-item `return_receipts`; put `return_receipts: true` at the top level.
Use the live tool's bounds. All items in a managed batch need `change`; do not
mix managed and legacy writes. A crash can commit a prefix, so retry that exact
managed batch rather than assuming it rolled back.

For confirmed withdrawals, use a higher change version with `operation: retract`
and empty `text`, under the same logical identity and appropriate write grant.
Retraction hides managed records from updated readers; signed history and
already copied plaintext remain. Legacy notes and blobs have separate lifetimes.

## Freshness and coverage

Keep these concepts distinct in the normalized text or a separate collection
receipt, using ISO 8601 UTC timestamps and explicit `unknown` values:

| Field | Meaning |
| --- | --- |
| Source event/updated time | When the provider says the event or revision happened |
| Measurement period | The interval a metric describes, including its timezone |
| Observed time | When this source version was actually read |
| Last checked | The last attempt to poll this selected source scope |
| Last successful collection | The last completed, acknowledged collection for that scope |
| Coverage | Filters, selected fields, pages completed, remaining cursor and exclusions |
| State | Current, partial, stale, failed or unknown, with the policy/reason |

These are importer conventions, not extra native HC API fields or automatic
freshness enforcement. A connector must populate them from real evidence. Keep
collection receipts separate from content revisions so unchanged records do not
look newly authored on every poll. Never advance success on a failed request.

## Readback

Read the receipt from `structuredContent` or its equivalent text content once.
The receipt reports `durability: local_log`, `replication: not_checked` and one
record ref/hash per item. Versioned capture returns `retry_safe: true` for
observed history, not a global exactly-once guarantee across disconnected nodes.

Call `record` with the returned `ref`, `format: structured`, and sufficient
`max_chars`/`max_output_chars`. Compare text, source identity and change version;
check clipping before declaring a match. Search discovery alone is insufficient
when it returns a prior version or clipped text. Ingestion time comes from
`ingested_at_ms`; capture metadata is explicitly a producer claim, not proof of
provider authenticity. A timeout leaves verification pending, never complete.

Older writers without versioned capture need an external deduplication ledger
and reconciliation after uncertain writes. Do not call them retry-safe. If the
requested correctness depends on managed changes, report the version gap.
