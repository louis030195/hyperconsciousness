<!-- screenpipe — AI that knows everything you've seen, said, or heard -->
<!-- https://screenpipe.com -->

# Publishing HC

Keep Cargo.toml, Cargo.lock and package.json versions equal. Bump the version in
a normal reviewed change on main. The release workflow automatically builds and
publishes that version once, after its tests pass. A matching `v<version>` tag
push or a manual workflow dispatch can also start it. Existing releases are
never overwritten; corrections require a new version.

Five native runners test and build the exact source revision. Publishing needs
all five jobs, then creates a GitHub release with binaries, install.sh and
SHA256SUMS. Alpha versions are marked prerelease. Only the publication job has
repository write permission. No publishing token or cloud credential is needed.

The installer discovers the most recently published release, including alphas,
then pins all downloads to that tag. Set `HC_VERSION=v0.1.0-alpha.5` to select an
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
