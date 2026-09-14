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
npm pack --dry-run
cargo package --locked
```

This repository ships the Rust engine, CLI, and agent skills. Client apps are
maintained separately. HTTP changes must preserve grant and OAuth boundaries.

## Protocol changes

Changes to encrypted formats, signatures, grants, recovery, sync, or durable
state must update the relevant specification or constraint document and include
tests for malformed, interrupted, replayed, and unauthorized inputs. Never add
real keys, grants, private records, device addresses, or personal paths to a
fixture.

By contributing, you agree that your contribution is licensed under MIT.
