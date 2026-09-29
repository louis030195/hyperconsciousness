---
name: hc-ingest-marketing
description: Import selected Buffer, HeyReach or Loops campaign, post and delivery records into HC with provider status, audience scope and metric freshness preserved.
---

# Ingest marketing tools

Read the shared [HC ingestion contract](../hc-ingest/SKILL.md) first. It covers
destination scope, sensitive fields, managed writes, retry recovery and readback.
Use this source recipe only for an authorized import.

## Select provider and account

Verify the authorized workspace, social profiles or campaign IDs using an
existing reader/export. Read only the requested campaigns and reporting period.
Ingestion does not authorize posting, enrolling contacts, launching sequences
or changing suppression lists. Use current provider schemas and API versions.

## Preserve statuses and measurements

For Buffer, keep profile/post identity, draft/scheduled/published state,
scheduled time with timezone, published URL and provider metrics update time.
For HeyReach, retain campaign and selected lead/activity identity, step,
reply/delivery status and event date. For Loops, distinguish draft/template,
send attempt, delivered, bounced and unsubscribed states as reported.

Do not label scheduled content published, API acceptance delivered or an open
tracking event human engagement. Totals may be cumulative snapshots rather than
daily increments; record their basis and never sum successive snapshots as new
activity. Old provider totals remain old even when fetched successfully today.

Choose aggregate campaign metrics for shared reporting when individual contact
records are unnecessary. Exclude recipient lists, private replies and signed
links unless their content is explicitly in scope. When authorized replies are
included, keep the actual author and thread context, separate from generated
outreach drafts. Do not follow embedded unsubscribe links during ingestion.

## Verify

Reopen a selected post/campaign and its reported state. Compare one metric's
period/basis and provider timestamp. Report scheduled versus published counts
separately, including pagination, missing replies and unavailable metrics.
