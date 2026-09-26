# HC Atlas

A general HC dashboard with original Escher-inspired geometry: impossible stairs,
isometric tessellations, orbital diagrams, and a green-and-parchment palette.

**[UI guide and screenshots](docs/ui/README.md)** covers the four views, file
inspection, keyboard shortcuts, sidebar resizing, and loading behavior.

This is an optional, independently packaged Next.js client in the HC repository. HC's Rust core, storage format, access rules,
and release remain unchanged. The client renders metadata from HC's existing CLI;
it does not implement another storage engine or authority layer.

## Run locally

Requires an existing HC installation on PATH, a file-backed local brain, Node.js
22 or later, Bun for the checked-in lockfile/test runner, and the system `du` utility.

```sh
bun install --frozen-lockfile
bun run build
bun run start
```

Open <http://127.0.0.1:3217>. For development, use `bun run dev`.
There is no new login: the server runs under your local OS account and uses that
account's existing HC identity. This is not a hosted team access portal.

Optional server environment variables, set before starting:

| Variable | Default | Purpose |
| --- | --- | --- |
| `HC_DASHBOARD_DIR` | `~/.brain` | Existing local store, an absolute path is recommended |
| `HC_DASHBOARD_BINARY` | `hc` | Existing CLI executable |
| `HC_DASHBOARD_NAME` | `My brain` | Workspace display label |

## Views and interpretation

- **Overview:** signed record counts, allocated local storage, device identity,
  device histories, and configured peers. Counts include policy and audit records.
- **Stored files:** newest file manifest metadata, filename filtering, versions,
  logical size, chunk availability, and a keyboard-accessible metadata dialog.
- **Your topology:** locally held author histories and configured replication
  routes. No peer connection or sync is triggered.
- **Identity & access:** HC's authority description and issued grant inventory.
  A future expiry does not mean a grant is currently effective. Revocations and
  grant chains remain HC's responsibility.

Storage measures disk allocation for `log`, `blobs`, and `cache`. It excludes
projected folders, external backups, and other directories. It is not the size
of readable or unique content. The staircase is illustrative, not a data chart.

The API uses `hc status`, `hc --version`, `hc peers`, `hc files --json`, and
`hc grants`. Browser input never becomes a command, executable, or filesystem path.
Overview results are cached in memory for 15 seconds. The file inventory runs
as one shared background job: the API returns immediately, the UI polls every two
seconds with elapsed time, and repeat visits reuse the completed snapshot.
Reinspect explicitly starts a refresh while keeping the previous rows visible.
A failed refresh keeps that snapshot and shows its original inspection time plus
an error. A failed first scan stops polling and waits for an explicit retry.
Snapshots remain in server memory until it exits; no decrypted inventory is saved
to disk. File scans stop after ten minutes, other HC commands after 45 seconds,
and browser requests after 20 seconds. Command output is bounded at 8 MiB.
Files and grants return at most 500 entries with an explicit total/truncation
marker. An incomplete inspection never becomes an empty or invented inventory.

The app supports the `hyperconsciousness.file-inventory.v1` JSON contract and
the status/grant text formats represented in the parser tests. Unsupported
formats, locked stores, missing CLIs, and Keychain-only identities may be
unavailable. Opening an absent or empty store does not initialize it.

## Local access boundary

Both launch scripts bind to loopback. Metadata routes validate the local Host,
same-origin browser context, and a custom request header, reject unsupported
operations, and return `Cache-Control: no-store`. There are no content downloads,
analytics, third-party assets, or browser-persisted inventories. HC performs its
own key handling; key bytes are never returned by this app.

This local OS-account boundary is not user authentication. Other local processes
with access to the account can query it. Do not expose this server through a
public interface or tunnel. A hosted/team client needs the existing HC access
adapter and per-user authorization before deployment.

## Validate

```sh
bun run check
bun test tests
bunx playwright install chromium
bun run test:e2e
bun run build
```

Unit tests cover output contracts, rejected local-request contexts, and the
no-initialization guarantee. Browser tests use clearly synthetic fixture data
for filtering, dialog keyboard behavior, failures, and responsive layout, plus
real HTTP checks for blocked requests. They do not change a real brain.

Code is grouped into `lib/hc.ts` (bounded CLI adapter), `lib/model.ts` (contracts
and parsing), one API route, the React dashboard, original SVG geometry, and CSS.
There are no new sync jobs, cloud credentials, permission mutations, or ingestion
providers in this client.
