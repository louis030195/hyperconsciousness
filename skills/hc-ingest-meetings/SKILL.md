---
name: hc-ingest-meetings
description: Import selected meeting notes, transcripts or Zoom and Cal.com records into HC, separating scheduling, attendance, speaker evidence and derived decisions.
---

# Ingest meeting context

Read the shared [HC ingestion contract](../hc-ingest/SKILL.md) first. It covers
destination scope, sensitive fields, managed writes, retry recovery and readback.

## Select artifacts

Use existing authorized Zoom, Cal.com, calendar or transcript access, or a
user-selected export. Verify the account, meeting identifiers and time range.
Collect only artifacts available to that account and permitted for the chosen
destination. Do not enable recordings, invite participants or change meetings.
Google Workspace records also have a dedicated `hc-ingest-google-workspace`
recipe when that source is in scope.

## Keep evidence types separate

A Cal.com booking or calendar event establishes scheduling. Attendance reports,
recordings, transcripts and human notes establish different facts. Preserve
cancelled, rescheduled, no-show and completed states as the source reports them.
Keep recurring occurrences distinct, including timezone and original event ID.

For transcripts, preserve artifact ID, meeting ID, segment ordering, timestamps
and speaker labels. Mark unidentified speakers and uncertain attribution. A
speaker label is not enough to merge identities across meetings. Do not include
private side conversations or unrelated recordings in shared summaries.

For generated notes, use `material: derived` and retain actual source refs or
external artifact pointers. Distinguish what was said, agreed, proposed and later
verified. Preserve owner/date uncertainty rather than turning an inferred next
step into a commitment. Do not send follow-ups while importing.

Keep large audio/video assets as authorized pointers unless media storage was
requested. Never store recording passcodes or signed download URLs as durable
source links. Chunk long text at stable segment boundaries; report omitted
segments and retain a manifest so retries do not duplicate chunks.

## Verify

Reopen one segment and its meeting context, then any derived decision note.
Check dates, speakers, source links and the distinction between booked and
attended. Report missing transcripts or uncertain attendance explicitly.
