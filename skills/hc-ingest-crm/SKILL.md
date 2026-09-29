---
name: hc-ingest-crm
description: Import selected Attio or HubSpot contacts, companies, deals, notes and task records into HC without changing CRM data or merging uncertain identities.
---

# Ingest CRM

Read the shared [HC ingestion contract](../hc-ingest/SKILL.md) first. It covers
destination scope, sensitive fields, managed writes, retry recovery and readback.
Use this source recipe only for an authorized import.

## Select the CRM workspace

Use existing Attio or HubSpot access and verify workspace plus selected objects,
record lists and properties. Read their current schemas before mapping fields;
custom properties and status options differ by workspace. Importing context does
not authorize changing deals, contacts, owners or tasks in the CRM.

## Preserve relationships

Use workspace/object/record ID as identity, not a name or email address. Preserve
company/contact/deal links as explicit relationships. Similar names, shared
email domains and personal mailboxes do not prove two records are the same
person. Keep ambiguous matches separate and report them.

Select business context, current stage, owner, next step and appropriate notes.
Retain note author, note date, source update time and any attached communication
reference. Separate a salesperson's estimate, customer statement, signed
agreement and collected payment. A closed-won status alone proves neither
payment nor a deployed product.

Exclude private coaching, sensitive personal notes and unnecessary contact
fields from shared ingestion. Page notes, activities and associations separately;
a record summary does not prove its complete communication history was read.
Retain field absence and deleted-record evidence without filling unknown values.

## Verify

Read back a deal with its company/contact links and one dated note. Confirm
field selection and uncertain identity matches survived normalization. Report
which objects and properties are covered and whether activity history is partial.
