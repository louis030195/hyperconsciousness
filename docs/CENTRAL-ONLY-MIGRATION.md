<!-- screenpipe — AI that knows everything you've seen, said, or heard -->

# Move an existing brain to one trusted node

HC now serves each store from one authoritative node. Phones, other computers,
and agents connect through authenticated MCP/HTTP access. The peer socket,
SSH, relay, peer discovery, and periodic peer sync commands are removed. A
central node can be self-hosted; it does not need a vendor-hosted HC service.

Before replacing an older CLI, stop and uninstall any peer-sync scheduler with
that older CLI (`hc service uninstall --dir <store>`). The new CLI does not run
or manage the old scheduler. Keep a copy of each existing store and its recovery
kit until migration has been checked. Do not delete an old node just because a
client can sign in.

Choose the node that will own the store. If its existing store already contains
the desired history, keep using that directory. Where old nodes have different
signed history, export an encrypted `hc bundle` on each old node and import the
bundles into the chosen node with `hc import`, using the existing authorized
identity for that brain. Bundle import validates signatures, author chains, and
current membership; it does not create or bypass missing keys. Keep separate
personal and company stores separate throughout this process. Verify the
author heads, expected records and file bytes on the chosen node before
retiring any old copy.

Create narrow grants on the chosen node and expose `hc mcp --as <grant>` or
`hc serve-http --as <grant>` through node-owned TLS. For a hosted access pack,
clients use `hc setup <connection.json> --codex`, `hc login`, and `hc status
--remote`. A client's configured connection, login, or successful status alone
does not prove its intended records are accessible; read a known allowed record
and check a known denied one. See [hosted access](HOSTED-ACCESS.md) and
[company access](COMPANY-ACCESS.md).

Encrypted S3-compatible object storage remains an optional **backup for the
central node**. Configure it there with `hc remote`, run `hc push`, and test
`hc pull` into an isolated authorized recovery store. It is not a second live
writer or a phone sync path. `hc recovery verify`, `hc witness verify`, and a
fresh-identity recovery drill remain separate checks. A bucket upload or a
valid bundle is not by itself proof that files can be decrypted and restored.

The old peer-oriented protocol and design documents remain as historical
format context. They do not describe supported operation of this CLI.
