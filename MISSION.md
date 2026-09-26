<!-- screenpipe — AI that knows everything you've seen, said, or heard -->

# Mission and repository boundary

HC is independent, private, decentralized knowledge storage and context access
for humans and agents. It preserves useful records across devices and gives
callers scoped, expiring, auditable access. It works without Screenpipe, a
particular model, or a required hosted service.

## What belongs here

- Signed, encrypted records and blobs, replication, recovery and independently
  encrypted spaces. Durable logs are authority; indexes are rebuildable views.
- Identity, grants, current membership, revocation and narrowly scoped opaque
  credential capabilities. Discovery is not permission.
- Bounded retrieval, source references, capture provenance, retry recovery,
  corrections and retractions with explicit guarantees and limitations.
- CLI/MCP/HTTP interfaces, operating skills, and thin source/transport adapters.
  Screenpipe, files and harness handoffs use generic storage contracts.
- Tests, evals, documentation and packaging that make those capabilities reliable.
- The optional `dashboard/` local, read-only metadata inspector. It consumes the
  existing CLI contracts and has its own package and dependencies. It is not
  bundled into the engine, CLI releases or npm wrapper. This is a narrow
  repository exception for the HC dashboard requested by the maintainer; it
  does not admit hosted/team clients or a second authorization layer.

## What stays outside this repository

Other client applications, agent planners, model routing, autonomous tool execution,
context-window assembly, automatic skill activation, outbound business workflows,
and device control belong to separate clients or harnesses. HC can store their
artifacts and expose authorized APIs without owning their execution.

HC does not replace Screenpipe's capture database, require a Screenpipe account,
become a CRM or collaboration app, or add blockchain consensus/token economics.
A captured instruction or tool description remains evidence until a caller
explicitly adopts it through its own trusted workflow. A keyless storage provider
receives ciphertext, never the keys or authority needed to answer private queries.

Compatibility endpoints and background **replication** services remain valid.
The words "mobile", "company", "skill" or "daemon" do not themselves indicate
scope creep. Judge the responsibility being added, its authority and dependency
direction. Website/docs work is also valid; a website is not a bundled client.

## Admission test for a change

State the concrete user outcome and the smallest complete change that achieves
it. Identify the existing contract it extends and why the work belongs in the
engine, an adapter, or an external harness/client. Preserve legitimate work:
rejecting every feature is as wrong as accepting every feature.

A fix should not quietly introduce a new platform, service, tool family, key
system, framework or mandatory provider. New dependencies and library modules
need a concrete purpose and a simpler-alternative assessment. No line-count,
file-count or arbitrary tool-count target substitutes for that reasoning.

Use observable outcomes and relevant failure cases as acceptance criteria.
Configured is not synchronized; uploaded is not recoverable; retracted is not
erased; encrypted storage does not hide returned plaintext from its recipient.
Leave unsupported guarantees and missing evidence explicit. When existing
behavior already meets the request, verification with no change is success.

This charter resolves the older PRD's Screenpipe-centric positioning. It does not
rewrite historical protocol guarantees. An intentional mission change should be
reviewed as such, with its evidence and affected eval cases visible, rather than
silently weakening the checks to pass an unrelated implementation.

See [the scope evals](evals/scope/README.md) for git-backed cases and review rules.
