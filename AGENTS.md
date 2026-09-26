<!-- screenpipe — AI that knows everything you've seen, said, or heard -->

# Working on HC

Read [MISSION.md](MISSION.md) and the relevant existing contract before planning
a change. Keep HC independent of Screenpipe and of any agent harness. Complete
the user's requested outcome with the smallest justified implementation; do not
add adjacent product features or block legitimate work merely to minimize code.
A verified no-change result is valid when the request is already satisfied.

Run `npm run eval:scope` for repository boundary checks and evaluator tests, plus
the implementation checks in CONTRIBUTING.md appropriate to the change. These
checks cannot prove semantic mission alignment. Review the actual diff using
[the scope rubric](evals/scope/RUBRIC.md), state limitations, and include the
mission fit and relevant regression evidence in the PR. Do not change the
charter, policy inventory or expected answers just to make an unrelated patch
pass. Keep model trials and private transcripts out of committed fixtures.

## Optional local dashboard

HC includes [HC Atlas](dashboard/README.md), a read-only dashboard for storage,
file metadata, identity/access and configured peers. An optional authenticated
MCP reader enables Records search and previews; see the dashboard README.
Use it when a user wants a visual view of their HC store. The [UI guide](dashboard/docs/ui/README.md)
includes screenshots and keyboard shortcuts.

From the repository root, enter `dashboard/`, run `bun install --frozen-lockfile`
and `bun run build` on first use (rebuild after source changes), then run
`bun run start`. Check whether the dashboard is already running at
<http://127.0.0.1:3217> before starting another process. Share that URL with the
user and verify it responds before reporting it as running. Keep the server
process available for the session; Ctrl+C in its terminal stops it.

The dashboard defaults to `~/.brain`. For another existing store, set
`HC_DASHBOARD_DIR` before starting it; see its README for prerequisites and
configuration. Confirm the intended store rather than assuming personal and
company HC are interchangeable. Never expose the server beyond loopback.

Dashboard startup is optional and separate from HC setup and CLI commands.
Reading these instructions does not require starting it. Do not add automatic
startup, browser opening, or dashboard lifecycle handling to the CLI.
