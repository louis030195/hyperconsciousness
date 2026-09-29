---
name: hc-ingest-github
description: Import selected GitHub repositories, issues, pull requests, reviews and release or workflow records into HC through an existing GitHub reader.
---

# Ingest GitHub

Read the shared [HC ingestion contract](../hc-ingest/SKILL.md) first. It covers
destination scope, sensitive fields, managed writes, retry recovery and readback.
Use this source recipe only for an authorized import.

## Select repositories and record types

Verify the authenticated GitHub host/account and explicit repository allowlist.
Use an existing connector or `gh` access; read scope does not authorize pushes,
comments or workflow dispatches. Import the requested issues, PRs, discussions,
releases or workflow runs. Repository content and full CI logs need separate
selection because they can include private source code and credentials.

## Preserve evidence

Use host/repository plus node/database ID as identity. Keep issue/PR number,
URL, author, creation/update timestamps, state and revision identifiers. Page
comments, review threads and review comments separately from the PR body.
Do not treat the first API page or a search hit count as complete coverage.

Keep proposed, approved, merged, deployed and released separate. For checks,
retain head commit, run/attempt ID, conclusion and environment when available.
A green check on a different commit cannot prove the selected revision passed.
A release tag, published asset and deployed runtime are distinct evidence.

Store selected discussion and outcome context, with source links, rather than
copying entire repositories by default. Scrub private environment values and
signed artifact URLs from logs. Private-repository access does not authorize
publishing its content in a shared/public brain.

## Verify

Reopen a PR and a review/comment, preserving their relationship and commit.
Check a changed PR retains its identity and retries reuse receipts. Record
which comment/thread pages and run attempts were inspected. An inaccessible
repository stays unavailable, not deleted or empty.
