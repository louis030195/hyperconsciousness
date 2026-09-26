<!-- screenpipe — AI that knows everything you've seen, said, or heard -->

# Hyperconsciousness (`hc`)

HC is an encrypted, append-only knowledge store for humans and agents. It keeps
signed records in sync across devices. You choose what an agent can access and
for how long through scoped, expiring grants.

The repository contains the Rust engine, CLI, MCP/HTTP server, and agent skills,
along with the optional local dashboard described below. Desktop, iOS, Android,
and mobile web apps are outside its scope. Private Companion and agent
orchestration are maintained separately.

HC is a developer alpha, so APIs and commands may change. No independent
security audit is claimed. Read the [security limits](docs/CONSTRAINTS.md) before
using it for important data. The package is `hyperconsciousness`; run it with `hc`.

## Local dashboard

Use the optional [HC Atlas dashboard](dashboard/README.md) to inspect storage,
file metadata, identity, grants, and configured peers. You can navigate with the
keyboard or use its command menu. The [UI guide and screenshots](dashboard/docs/ui/README.md)
show each view.

The dashboard runs locally and requires an existing HC installation. Install it
separately from the CLI. Agents can start it when a visual inspection would help;
the [agent startup notes](AGENTS.md#optional-local-dashboard) explain how.

Check the [prerequisites](dashboard/README.md#run-locally), then run these commands
from the repository root:

```sh
cd dashboard
bun install --frozen-lockfile
bun run build
bun run start
```

Open <http://127.0.0.1:3217>, or reuse the dashboard there if it is already running.
Its server keeps running when you close the browser and stops when you end the
server process. Startup is manual: HC setup and CLI commands do not launch the
dashboard or open a browser. The dashboard inspects local metadata; it does not
provide hosted team access.

## Install from source

Install Rust with `rustup`. This checkout pins Rust 1.88.0. Linux builds also
need native headers; on Ubuntu or Debian, install them with:

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

Build this alpha from the repository checkout. The npm registry package is not
its source. The repository retains npm packaging scripts for compatibility and
tests them in CI.

## Try an isolated store

Try HC in a new directory. Passing that directory to every command keeps this
example separate from an existing personal store:

```sh
HC_STORE="$PWD/hc-demo"
hc start --dir "$HC_STORE"
hc write "A demo note" --tags demo --sensitivity normal --dir "$HC_STORE"
hc read --dir "$HC_STORE"
hc status --dir "$HC_STORE"
```

`hc read` displays local records without a full integrity check. It can display
a record whose signature was modified, and it can exit successfully after
withholding a record whose ciphertext was modified. Grant-scoped MCP reads
verify history and reject those mutations. To validate backups, use the
documented recovery verification and drill workflow.

## Give an agent limited access

For an agent running on the same trusted node, grant access to that node's
device identity. This example allows one day of read-only access to normal
notes tagged `demo`:

```sh
HC_DEVICE="$(hc id --dir "$HC_STORE" | cut -d: -f2)"
hc grant "$HC_DEVICE" --kinds note --tags demo \
  --sensitivity normal --days 1 --dir "$HC_STORE"
hc grants --dir "$HC_STORE"
```

Copy the grant id into your MCP client configuration. Use absolute paths for
your HC executable and the store you chose:

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

Grants limit what the server returns. A process with access to the owner's OS
account, files, or keys still has that access; grants do not sandbox it. Hosted
model providers can see the plaintext returned through their grants.

The HTTP server supports OAuth/DPoP, capture, and owner-approval APIs for
separate clients. It has no bundled application or approval UI. Existing
`/mobile/...` API names are preserved for compatibility; removed client pages
and assets return 404.

## Keep company and personal data separate

Initialize company and personal stores independently. Give each its own runtime
identity and credentials, and select the store with an explicit `--dir` path.
Directory names alone provide no OS isolation. Run untrusted company agents
under a separate OS account or on a separate host.

Do not put API keys, recovery phrases, or private brain data in Git, skills,
container layers, or machine images. Credential adapters retain secret values;
HC stores opaque capability references and grants specific operations.

## Documentation

- [Mission and scope](MISSION.md) and [scope evals](evals/scope/README.md).
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
