---
name: hc-ingest-infra
description: Import scoped operational summaries from AWS, Google Cloud, Cloudflare, Vercel or Sentry into HC through existing read access, excluding secrets and raw production payloads.
---

# Ingest cloud operations

Read the shared [HC ingestion contract](../hc-ingest/SKILL.md) first. It covers
destination scope, sensitive fields, managed writes, retry recovery and readback.
Use this source recipe only for an authorized import.

## Select operational scope

Verify provider account/project, environment and region using existing CLI/API
identity reads. Name the services, deployments, issues or reporting interval
requested. Use short-lived or renewable provider authentication already in place;
do not create permanent keys, change IAM or prolong sessions during ingestion.
An expired login is an authentication gap, not evidence the service is down.

## Normalize operational evidence

- AWS/Google Cloud: selected resource state, deployment revision, bounded health
  summaries and aggregate usage/cost reports with their measurement periods.
- Cloudflare/Vercel: selected project/deployment IDs, commit, target environment,
  deployment state and separately verified serving state when available.
- Sentry: selected project/issue/event identity, release, first/last seen,
  status and bounded sanitized error context. An issue marked resolved does not
  prove no affected users remain.

Use provider/account/region/resource or report identity so similarly named
staging and production resources never collapse. Preserve observation time and
source update time independently. Label cached status, partial logs and delayed
cost data. Deployment configuration alone does not prove runtime health.

Do not import environment-variable values, keys, connection strings, secret
manager contents, session tokens, customer request bodies or complete crash
payloads. Select useful error types and stack locations after reviewing possible
personal data. Operational names and topology can also be private; use the
approved destination, not a public example repository.

## Verify

Read back one selected deployment/issue/report with its environment and revision.
Report which service signals were actually checked and which remain unknown.
A status page, successful API poll and healthy workload are separate evidence.
