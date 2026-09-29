---
name: hc-ingest-google-workspace
description: Import selected Gmail, Drive, Docs, Calendar and available Meet records into HC through existing Google access or exports, keeping mailboxes and sharing scopes separate.
---

# Ingest Google Workspace

Read the shared [HC ingestion contract](../hc-ingest/SKILL.md) first. It covers
destination scope, sensitive fields, managed writes, retry recovery and readback.
Use this source recipe only for an authorized import.

## Select each surface

Verify the Google account and allowed mailbox, folder/shared drive, calendars or
meetings separately. Read access to one does not authorize the others. Use an
existing connector/export and current Google API documentation. Do not enable
domain-wide delegation, impersonate teammates or grant new OAuth scopes as a
side effect. A company email address does not make all mailbox content shared.

## Source-specific records

- Gmail: preserve account-scoped message ID, thread ID, headers needed for
  chronology and actual labels. Drafts and sent mail are different states.
  Prefer the selected plain-text MIME body, decode it correctly, and keep quoted
  history distinguishable. Exclude attachments and signatures unless needed.
  Page the requested history; handle an invalid incremental history cursor with
  an explicit bounded rescan rather than declaring an empty inbox.
- Drive/Docs: preserve drive/account ID, file ID, revision or modification time,
  title, MIME type and durable link. Export only selected content in a supported
  format. Shortcuts and shared-drive items need explicit resolution. A moved file
  is not deleted; inability to read a file is not a deletion receipt.
- Calendar: retain calendar/event IDs, recurring-event instance identity,
  organizer, start/end timezone and cancellation state. Keep booked, rescheduled,
  cancelled and attended distinct. The event alone does not prove attendance.
- Meet: use only available, authorized transcripts/recordings or meeting notes.
  Keep meeting identity, artifact source and speaker/timestamp evidence. A
  calendar entry is not a transcript, and generated notes are derived content.

Keep meeting recordings outside HC text notes unless media ingestion is separately
requested. Summaries must identify the underlying records and whether the source
was a transcript, notes or just the invitation.

## Verify

Read back selected messages/documents and a recurring event instance when used.
Check source dates survive import and drafts are not labeled sent. Report the
scope and freshness of each Google surface independently, including unavailable
transcripts, excluded attachments and unfinished pagination.
