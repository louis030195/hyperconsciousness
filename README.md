<!-- screenpipe — AI that knows everything you've seen, said, or heard -->

# Hyperconsciousness (`hc`)

An encrypted, append-only knowledge store for humans and agents. HC signs and
seals records, syncs them between devices, and gives agents access through
scoped, expiring grants.

This repository contains the Rust engine, CLI, MCP/HTTP server, and agent skills.
It does not ship a desktop, iOS, Android, or mobile web app. Private Companion
and agent orchestration are maintained separately.

**Developer alpha.** APIs and commands may change. No independent security audit
is claimed. Read the [security limits](docs/CONSTRAINTS.md) before entrusting
important data to it. The package is `hyperconsciousness`; its executable is `hc`.

## Install from source

Install Rust with `rustup`; this checkout pins Rust 1.88.0. Linux builds also
need native headers. On Ubuntu or Debian:

```sh
sudo apt-get install build-essential pkg-config libssl-dev libdbus-1-dev
```

Build the source on macOS or Linux:

```sh
git clone https://github.com/louis030195/hyperconsciousness.git
cd hyperconsciousness
cargo build --release --locked
mkdir -p "$HOME/.local/bin"
install -m 755 target/release/hc "$HOME/.local/bin/hc"
export PATH="$HOME/.local/bin:$PATH"
hc --help
```

On Windows, use `cargo build --release --locked` and run
`target\release\hc.exe`. Add the binary's directory to your PATH if needed.

The npm packaging scripts are retained for compatibility and tested in CI.
The registry package is not the source of this alpha; use this checkout.

## Try an isolated store

Choose a new directory. Pass it explicitly to every command so this example
cannot open an existing personal store:

```sh
HC_STORE="$PWD/hc-demo"
hc start --dir "$HC_STORE"
hc write "A demo note" --tags demo --sensitivity normal --dir "$HC_STORE"
hc read --dir "$HC_STORE"
hc status --dir "$HC_STORE"
```

`hc read` is a local display command, **not a full integrity check**. It can
display a record with a modified signature and can exit successfully after
withholding a record with modified ciphertext. Grant-scoped MCP reads verify
history and reject those mutations. Use the documented recovery verification
and drill workflow when validating backups.

## Give an agent limited access

For a local agent on the same trusted node, use that node's device identity as
the grant subject. This example grants one day of read-only access to normal
notes tagged `demo`:

```sh
HC_DEVICE="$(hc id --dir "$HC_STORE" | cut -d: -f2)"
hc grant "$HC_DEVICE" --kinds note --tags demo \
  --sensitivity normal --days 1 --dir "$HC_STORE"
hc grants --dir "$HC_STORE"
```

Copy the grant id into your MCP client configuration. Both paths must be
absolute and point to your chosen installation and store:

```json
{
  "mcpServers": {
    "hc": {
      "command": "/absolute/path/to/hc",
      "args": ["mcp", "--as", "<grant-id>", "--dir", "/absolute/path/to/hc-demo"]
    }
  }
}
```

MCP exposes `overview`, `request_access`, `access_status`, `search`, `recent`,
`record`, `remember`, `remember_many`, `use_secret`, and `files`. A tool's
presence does not grant permission to use it. Add `--write` only when the agent
needs capture access. Credential operations require a separate `USE` grant and
a signed device request. For company members, groups, multiple devices and
agents, use [company gateway access](docs/COMPANY-ACCESS.md). Company mode checks
current membership on every tool call and requires client-side request signing.

```sh
hc revoke <grant-id> --dir "$HC_STORE"
hc audit --dir "$HC_STORE"
```

Grants constrain the server's responses. They do not sandbox a process that
already has access to the owner's OS account, files, or keys. Hosted model
providers can see plaintext returned through their grants.

The HTTP server supports OAuth/DPoP, capture, and owner-approval APIs for
separate clients. It has no bundled application or approval UI. Existing
`/mobile/...` API names are preserved for compatibility; removed client pages
and assets return 404.

## Keep company and personal data separate

Use independently initialized stores, explicit `--dir` paths, and separate
runtime identities and credentials. A directory name is not an OS security
boundary. Run untrusted company agents under a separate OS account or host.

Do not put API keys, recovery phrases, or private brain data in Git, skills,
container layers, or machine images. Credential adapters retain secret values;
HC stores opaque capability references and grants specific operations.

## Documentation

- [Operator skill](skills/hyperconsciousness-ops/SKILL.md): sync, workspaces, grants, secrets,
  remote storage, services, and recovery commands.
- [Agent skill](skills/hyperconsciousness/SKILL.md): scoped knowledge discovery.
- [Architecture](docs/ARCHITECTURE.md) and [format specification](docs/SPEC.md).
- [Screenpipe backup adapter](docs/SCREENPIPE-ADAPTER.md): legacy SQLite and hybrid SQLite + Parquet archives.
- [Harness context plan](docs/HARNESS-CONTEXT-PLAN.md): bounded evidence, capture provenance, skills, handoffs and independent adapters.
- [Threat model and constraints](docs/CONSTRAINTS.md).
- [Failure cases](docs/EDGE-CASES.md) and [design decisions](docs/DECISIONS.md).
- [Roadmap](docs/ROADMAP.md), [contributing](CONTRIBUTING.md), and
  [security reporting](SECURITY.md).

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
npm test
npm pack --dry-run
cargo package --locked
```

MIT licensed. See [LICENSE](LICENSE).
