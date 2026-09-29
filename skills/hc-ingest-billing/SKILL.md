---
name: hc-ingest-billing
description: Import selected Stripe subscription, invoice, payment and refund records or aggregate billing reports into HC while keeping live/test accounts and revenue definitions distinct.
---

# Ingest billing records

Read the shared [HC ingestion contract](../hc-ingest/SKILL.md) first. It covers
destination scope, sensitive fields, managed writes, retry recovery and readback.
Use this source recipe only for an authorized import.

## Select Stripe scope

Verify the account, connected-account context when applicable, and live versus
test mode through existing read access. Select the object types and period needed
for the task. This skill reads Stripe; it does not charge, refund, cancel or
change subscriptions. Keep restricted keys inside the provider adapter.

## Preserve financial state

Use account/mode/object ID as identity. Preserve subscription, invoice, payment
and refund relationships, statuses, currencies and source dates. Store amounts
in their original units and use currency metadata when converting them; not all
currencies use the same number of decimal places. Distinguish recurring value,
invoiced amount, payment success, refunds, disputes and cash availability.

For aggregate reports, record the exact cohort, period, timezone, treatment of
trials/discounts/overdue invoices and excluded currencies. An active subscription
is not evidence of a paid invoice. Do not infer collected cash from an MRR total.
Avoid duplicating revenue by adding invoice totals to their payment objects.

Prefer aggregate or minimally identifying records in a shared brain. Exclude
payment instruments, client secrets, full billing addresses and customer portal
or hosted-payment URLs. Webhook events can be retried or arrive out of order;
retain event IDs and reconcile selected object state. An API error is not zero.

## Verify

Read back an invoice/payment relationship or one aggregate cohort and compare
amount, unit, currency and status. Report selected periods and last collection;
keep calculation assumptions visible for future agents.
