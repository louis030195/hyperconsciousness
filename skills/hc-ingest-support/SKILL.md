---
name: hc-ingest-support
description: Import selected Intercom, Zendesk or Discord support conversations into HC with thread, author, status and coverage evidence, excluding unrelated private content.
---

# Ingest support

Read the shared [HC ingestion contract](../hc-ingest/SKILL.md) first. It covers
destination scope, sensitive fields, managed writes, retry recovery and readback.
Use this source recipe only for an authorized import.

## Select the support surface

Verify the workspace/guild and chosen inboxes, channels or tickets with existing
API access. Use official bot/app tokens inside the connector. Never use Discord
user-session tokens or browser cookies. Public, private/shared and archived
threads can have different visibility; record each gap instead of broadening
access automatically.

## Normalize conversations

Preserve workspace/ticket or channel/thread/message IDs, source URLs, author type,
provider event/update times and current conversation state. Page conversation
parts and replies, not just ticket headers. Distinguish customer messages,
internal notes, bot/webhook mirrors and staff replies. Include relevant webhook
messages when the source is a feedback mirror; label duplicated mirrored events.

Keep a reported bug, proposed fix, shipped version and verified recovery as
separate facts. A closed ticket is an administrative status, not proof the
customer recovered. Preserve promises and responsible owners as statements with
source references, without creating follow-up tasks or sending replies.

Strip credentials, access links and unrelated customer identifiers from selected
logs. Attachments and recordings need explicit content selection. Internal notes
must not become customer-visible merely because the ticket also has public replies.
Use a destination whose audience matches the selected material.

## Verify

Reopen a conversation part and thread reply, checking authorship and public vs
internal state. Report history/attachment coverage, excluded channels and the
last successful read separately from a ticket's last update.
