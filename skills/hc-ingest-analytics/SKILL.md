---
name: hc-ingest-analytics
description: Import selected PostHog, GA4 or database analytics into HC as scoped measurements with query definitions, time windows, sampling and freshness evidence.
---

# Ingest analytics

Read the shared [HC ingestion contract](../hc-ingest/SKILL.md) first. It covers
destination scope, sensitive fields, managed writes, retry recovery and readback.
Use this source recipe only for an authorized import.

## Choose a measurement

Verify project/property/database identity with existing read access. Name the
business question, time window, timezone, event definition and aggregation grain.
For database sources such as Supabase, prefer approved views or bounded read-only
queries. Do not dump user tables, edit tracking or query an unrelated database.

## Preserve the metric contract

Store the query/report definition or a durable query reference, filters,
measurement window, units, currency when relevant, denominator, grouping and
provider execution/update time. Identify sampled, thresholded, estimated or
incomplete results. Retain null, missing, suppressed and zero distinctly.

Use stable identities that include project, metric/query definition, dimensions
and period. A changed query is not the same time series unless the definition
change is recorded. Late events can revise an old period; revisit an appropriate
overlap window and create a new managed version rather than another independent
copy of that period.

Prefer aggregates appropriate to the destination. User/session identifiers,
recordings, raw URLs and free-form event properties can contain personal data;
select them only when the task requires them. A successful fetch today does not
make an old provider snapshot current. Do not infer causal effects or revenue
from event counts alone.

## Verify

Compare one imported aggregate and its denominator against the source response,
including units, timezone and sample state. Read back its definition and period.
Report data through-date separately from query run time and import time.
