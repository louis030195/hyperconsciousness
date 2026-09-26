<!-- screenpipe — AI that knows everything you've seen, said, or heard -->

# Contributing

Hyperconsciousness is early and security-sensitive. Small, reviewable changes
with explicit failure cases are preferred.

## Development

Install Rust 1.88 or newer and the native dependencies listed in the README.
Before opening a pull request, run:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
npm test
npm run eval:scope
npm pack --dry-run
cargo package --locked
```

This repository ships the Rust engine, CLI, and agent skills. Client apps are
maintained separately, with the optional local read-only dashboard described in
MISSION.md as the sole exception. For dashboard changes, run `bun install
--frozen-lockfile`, `bun run check`, `bun test tests`, `bun run build`, and
`bun run test:e2e` from `dashboard/`, plus the root scope and packaging checks.
Keep its dependencies out of the engine and npm wrapper. HTTP changes must preserve grant and OAuth boundaries.

## Mission and scope review

Read [MISSION.md](MISSION.md) before proposing a feature. Include the user
outcome, ownership boundary, simplest complete implementation and verification
in the PR. The [scope suite](evals/scope/README.md) checks historical boundary
regressions and provides a balanced rubric for plans and diffs.

`npm run eval:scope` needs Node 20+ and a full git checkout. It performs no model
calls and never opens a private HC store. New runtime dependencies or library
modules require a deliberate inventory update and a rationale in the PR; do not
silently lower the standard to pass a feature. Existing approval/CODEOWNERS
review still applies. Green structural checks do not prove semantic alignment.

## Protocol changes

Changes to encrypted formats, signatures, grants, recovery, sync, or durable
state must update the relevant specification or constraint document and include
tests for malformed, interrupted, replayed, and unauthorized inputs. Never add
real keys, grants, private records, device addresses, or personal paths to a
fixture.

By contributing, you agree that your contribution is licensed under MIT.
