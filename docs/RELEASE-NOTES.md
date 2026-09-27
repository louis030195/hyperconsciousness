<!-- screenpipe — AI that knows everything you've seen, said, or heard -->
<!-- https://screenpipe.com -->

# HC alpha: native installation and hosted access

Prebuilt CLI binaries are available for Apple Silicon and Intel Macs, Linux
x86-64 and ARM64, and Windows x86-64. `SHA256SUMS` covers all release assets.

Install on macOS or Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/louis030195/hyperconsciousness/main/install.sh | sh
```

The installer selects a published release, verifies its archive checksum and
binary version, and installs to `~/.local/bin`. It never creates or opens a
brain. Add that directory to PATH if the installer asks. Linux binaries target
Ubuntu 24.04 or compatible glibc systems. macOS binaries are not notarized.
Windows users can download the ZIP and run `hc.exe`.

This release includes the generic `hc setup`, `hc login`, `hc status --remote`,
`hc mcp --remote` and `hc logout` commands previously used by the company pilot.
Organizations supply their own connection file and instruction skills. No
company endpoint, credentials, membership or source records ship in the binary.
Local storage and grant-scoped MCP commands retain their existing behavior.

It also includes the current main branch's bounded lexical recall and optional
HC Atlas record-browsing work. The dashboard remains separately installed and
manually started. Hosted access is read-only according to the server's grant;
setup alone does not prove ingestion freshness. HC remains a developer alpha.
