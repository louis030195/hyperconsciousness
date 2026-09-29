---
name: hc-ingest-slack
description: Import selected Slack channels, messages and thread replies into HC using existing authorized access, with edit, deletion and thread-coverage tracking.
---

# Ingest Slack

Read the shared [HC ingestion contract](../hc-ingest/SKILL.md) first. It covers
destination scope, sensitive fields, managed writes, retry recovery and readback.
Use this source recipe only for an authorized import.

## Scope and access

Verify the workspace ID and selected channel IDs with the installed Slack
connector or official API. Discover public/private channel permissions separately;
a missing scope on one type does not prove other channels are empty. Use existing
OAuth or an authorized export. Never extract Slack desktop tokens or cookies.
Don't install an app, join channels or request broader scopes during ingestion.

## Collect and preserve

Page channel history and fetch replies for selected threads separately. Search
results are discovery, not a complete history export. Record pagination gaps and
thread coverage, including replies posted later to old parent messages. Preserve
workspace/channel IDs, message timestamp as an opaque ID, thread parent,
author, provider edit timestamp and permalink. Use
`workspace/channel/message-ts` as identity; don't convert Slack timestamps to
floating point. Content revisions can change while the message ID stays stable.

Select message text and required context. DMs, private channels, Slack Connect
content and attachments require a destination appropriate to their audience.
Do not infer that all workspace members may read a copied message. File URLs
may be temporary or authenticated; don't archive bearer URLs or download every
attachment. Preserve bots/webhooks when relevant instead of silently omitting
them from a claimed full history.

Only retract when an authorized deletion event or other reliable source evidence
establishes removal. Pagination omissions and revoked access are coverage gaps.
Use an overlap window or provider cursor to reconcile edits and late replies.

## Verify

Read back a root message and a reply with their relationship intact. Check an
edit keeps its logical ID, retries reuse receipts, and excluded channels never
enter the payload. Report checked channels/time range and incomplete threads.
