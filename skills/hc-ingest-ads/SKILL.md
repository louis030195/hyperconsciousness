---
name: hc-ingest-ads
description: Import selected Google Ads or Meta Ads reports into HC with account identity, attribution settings, currencies, reporting periods and revision-aware metrics.
---

# Ingest advertising data

Read the shared [HC ingestion contract](../hc-ingest/SKILL.md) first. It covers
destination scope, sensitive fields, managed writes, retry recovery and readback.
Use this source recipe only for an authorized import.

## Establish account and reporting scope

Use existing authorized Ads API access or a user-supplied report. Verify the
customer/account, manager relationship when relevant, selected campaigns and
reporting timezone/currency. Keep credentials and developer tokens inside the
adapter. Ingestion does not authorize campaign, budget or conversion changes.
Use the provider's current supported API version and reporting fields.

## Preserve measurement meaning

Keep account/campaign/ad-group/ad IDs, reporting date or period, segmentation,
spend unit, currency, impressions, clicks, conversion definition and reported
conversion value. For Google Ads, distinguish cost micros from currency units.
For Meta, preserve action type and attribution window. Do not sum repeated total
rows with their segmented rows or assume similarly named conversions are equal.

Store the query/report definition and selected conversion actions. Separate
provider-attributed value from paid invoices or collected cash. Compute ROAS
only when value and spend share the intended currency, period and attribution
basis; label the basis and return undefined for zero spend. Do not imply profit.

Page reports and preserve partial/backfill state. Revisit recent periods for
conversion lag and adjustments without resetting historic checkpoints. Retain
measurement period, provider update time if available, last successful fetch
and HC receipt separately. Exclude user-level targeting or identifiers from
aggregate company reporting unless specifically needed and authorized.

## Verify

Read back a campaign-period row and compare spend conversion, dimensions and
conversion value with the source. Test a repeated page does not double-count.
Report missing accounts, periods, attribution settings and freshness evidence.
