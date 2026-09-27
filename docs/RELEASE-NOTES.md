<!-- screenpipe — AI that knows everything you've seen, said, or heard -->
<!-- https://screenpipe.com -->

# HC alpha.6: automatic native CLI updates

Installer-managed HC copies now check GitHub releases in the background at most
once every six hours of use. New launches pick up verified updates; current CLI
commands and MCP sessions continue without interruption. No updater service or
dashboard starts. Existing alpha.5 users must rerun the installer once.

```sh
curl -fsSL https://raw.githubusercontent.com/louis030195/hyperconsciousness/main/install.sh | sh
```

Use `hc update` to install now, `hc update --check` to inspect availability, and
`hc update --disable` or `--enable` to control automatic updates. Set
`HC_AUTO_UPDATE=0` to skip background checks for a process. Source/package-manager
builds and explicit version-pinned installs do not automatically opt in. Windows
ZIP users enable updates with `hc update --enable`.

Downloads use HTTPS, SHA-256 integrity checks and an executable version check.
Alpha clients follow newer alpha/stable releases; stable clients stay on stable
releases. Failed checks leave the installed version available. Local records,
credentials, team access and skills are unchanged.

Native archives and updater binaries are published for Mac ARM64/Intel, Linux
ARM64/x86-64 and Windows x86-64. Linux requires Ubuntu 24.04-compatible libraries;
Mac binaries are not notarized. HC remains a developer alpha.
