<!-- screenpipe — AI that knows everything you've seen, said, or heard -->
<!-- https://screenpipe.com -->

# Publishing HC

Keep Cargo.toml, Cargo.lock and package.json versions equal. Bump the version in
a normal reviewed change on main. The release workflow automatically builds and
publishes that version once, after its tests pass. A matching `v<version>` tag
push or a manual workflow dispatch can also start it. Existing releases are
never overwritten; corrections require a new version.

Five native runners test and build the exact source revision. Publishing needs
all five jobs, then creates a GitHub release with archives, raw updater binaries, install.sh and
SHA256SUMS. Alpha versions are marked prerelease. Only the publication job has
repository write permission. No publishing token or cloud credential is needed.

The installer discovers the most recently published release, including alphas,
then pins all downloads to that tag. Set `HC_VERSION=v0.1.0-alpha.6` to select an
exact release or `HC_INSTALL_DIR=/absolute/path` to choose its destination.
It validates the platform, archive checksum, contents and executable version
before replacing the installed binary. It does not modify shell startup files,
initialize a store, run login, or start a daemon or dashboard.

Test installer failure paths with:

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Keep company-specific profiles and skills in the company deployment. A company
bootstrap can call this installer, supply its own reviewed connection pack,
then run `hc setup`, `hc login` and `hc status --remote`.

## Automatic CLI updates

The shell installer enables automatic updates by placing `.hc-auto-update` next
to its binary. An explicit `HC_VERSION` keeps an installation pinned; installing
with `HC_AUTO_UPDATE=0` also leaves updates disabled. `hc update --enable` and
`hc update --disable` change this choice. ZIP users on Windows opt in explicitly.
Source builds and package-manager installations stay under their manager's control
unless the user explicitly enables HC updates.

When an opted-in binary runs a command, a quiet child checks for an update at most
once every six hours. Help/version commands never trigger a check. The child has
no stdin/stdout/stderr connection to MCP, has bounded network requests and exits
after one attempt. Offline failures and GitHub rate limits keep the working binary
and back off until the next interval. Nothing polls while HC is unused. A running
MCP session is never restarted; launch a new session to use the replaced binary.

`hc update` checks and installs immediately. `hc update --check` only reports a
newer eligible release. Alpha installations follow prereleases and stable releases;
stable installations accept only stable releases. Selection uses semantic versions
from the latest 100 published releases, ignores drafts/incomplete assets, and never
downgrades. `HC_AUTO_UPDATE=0` overrides background checks, not an explicit update.

The updater downloads only from the public HC GitHub repository over verified
HTTPS, validates the SHA256SUMS entry and executable version, then replaces the
binary in its installation directory. Checksums protect download integrity; they
are not signatures independent of GitHub/repository security. A process lock
serializes checks. A changed installation or an opt-out during download cancels
replacement. Unix uses atomic replacement; Windows keeps a rollback copy while
replacing the running executable. Loss of power can still leave temporary files.
No store, credential, session, grant, skill or dashboard is modified. Unix updates
require a user-owned install directory without group/world write permissions and
refuse sudo/root; managed system installs should use their package manager.

`semver` provides version/channel ordering and `self-replace` handles native
executable replacement, including Windows running-file semantics. They extend
CLI packaging only, not the engine or a required service. These are deliberate
additions to the scope dependency inventory. Raw release executables avoid adding
ZIP/gzip extraction dependencies or invoking downloaded shell code in the updater.

After upgrading a pre-updater release once with the installer, future releases
are automatic. Validate with `cargo test --locked`, which includes isolated native
replacement and CLI opt-out tests, plus the installer tests above. GitHub runs
these checks on every supported release platform.
