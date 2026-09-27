// screenpipe — AI that knows everything you've seen, said, or heard
// https://screenpipe.com

//! Release installation only. Never opens a brain, session, or agent configuration.
use fs4::fs_std::FileExt;
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const REPO: &str = "https://github.com/louis030195/hyperconsciousness";
const RELEASES: &str =
    "https://api.github.com/repos/louis030195/hyperconsciousness/releases?per_page=100";
const MARKER: &str = ".hc-auto-update";
const INTERVAL: u64 = 6 * 60 * 60;
const MAX_BINARY: u64 = 128 * 1024 * 1024;
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn fail(message: &str) -> io::Error {
    io::Error::other(message)
}

fn sibling(exe: &Path, name: &str) -> PathBuf {
    exe.with_file_name(name)
}

fn regular(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

fn enabled(exe: &Path) -> bool {
    let marker = sibling(exe, MARKER);
    std::env::var("HC_AUTO_UPDATE").as_deref() != Ok("0")
        && regular(&marker)
        && fs::read(marker).is_ok_and(|bytes| bytes == b"1\n")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn due(last: u64, now: u64) -> bool {
    last == 0 || now < last || now - last >= INTERVAL
}

fn last_check(exe: &Path) -> u64 {
    let path = sibling(exe, ".hc-update.lock");
    if !regular(&path) {
        return 0;
    }
    fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// Network work happens in a detached, quiet child, never on the MCP/CLI path.
pub(crate) fn maybe_start(command: &str) {
    if matches!(
        command,
        "help" | "--help" | "-h" | "version" | "--version" | "-V" | "update" | "__update"
    ) {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    if !enabled(&exe) || !due(last_check(&exe), now()) || writable_install(&exe).is_err() {
        return;
    }
    let mut worker = Command::new(exe);
    worker
        .arg("__update")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        worker.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    if let Ok(mut child) = worker.spawn() {
        // Reap in long-lived MCP processes; short CLI parents may exit first.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
    }
}

fn writable_install(exe: &Path) -> io::Result<()> {
    if !regular(exe) {
        return Err(fail("HC executable is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = unsafe { libc::geteuid() };
        for path in [
            exe,
            exe.parent()
                .ok_or_else(|| fail("missing install directory"))?,
        ] {
            let metadata = fs::metadata(path)?;
            if metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
                return Err(fail(
                    "HC updates require an owned installation without group/world write access",
                ));
            }
        }
        if uid == 0 {
            return Err(fail("run HC updates as the installing user, without sudo"));
        }
    }
    Ok(())
}

fn lock(exe: &Path) -> io::Result<File> {
    let path = sibling(exe, ".hc-update.lock");
    if fs::symlink_metadata(&path).is_ok() && !regular(&path) {
        return Err(fail("invalid HC update lock"));
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    if !FileExt::try_lock_exclusive(&file)? {
        return Err(fail("another HC updater is running"));
    }
    Ok(file)
}

pub(crate) fn run(args: &[String], background: bool) -> io::Result<()> {
    if args == ["--help"] {
        println!("hc update [--check | --enable | --disable]\nCheck/install a newer GitHub release, or control automatic checks.\nHC_AUTO_UPDATE=0 disables background checks for this process.");
        return Ok(());
    }
    if args.len() > 1
        || args
            .first()
            .is_some_and(|a| !matches!(a.as_str(), "--check" | "--enable" | "--disable"))
    {
        return Err(fail("usage: hc update [--check | --enable | --disable]"));
    }
    let exe = std::env::current_exe()?;
    writable_install(&exe)?;
    let mut guard = lock(&exe)?;
    let option = args.first().map(String::as_str).unwrap_or("");
    if matches!(option, "--enable" | "--disable") {
        let marker = sibling(&exe, MARKER);
        if option == "--disable" {
            match fs::remove_file(marker) {
                Ok(()) => (),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            }
        } else {
            let mut temp = tempfile::NamedTempFile::new_in(exe.parent().unwrap())?;
            temp.write_all(b"1\n")?;
            temp.as_file().sync_all()?;
            temp.persist(marker).map_err(|e| e.error)?;
        }
        println!(
            "Automatic HC updates {}.",
            if option == "--enable" {
                "enabled"
            } else {
                "disabled"
            }
        );
        return Ok(());
    }
    if background && (!enabled(&exe) || !due(last_check(&exe), now())) {
        return Ok(());
    }
    // Back off even after an offline/rate-limited attempt. No busy retry loop.
    guard.rewind()?;
    guard.set_len(0)?;
    writeln!(guard, "{}", now())?;
    guard.sync_all()?;
    let original = digest(&fs::read(&exe)?);
    // An older process may still be running after another updater replaced its path.
    verify_version(&exe, VERSION)?;
    let client = ureq::AgentBuilder::new()
        .https_only(true)
        .redirects(5)
        .timeout(Duration::from_secs(60))
        .user_agent(concat!("hc-updater/", env!("CARGO_PKG_VERSION")))
        .build();
    let fetch = |url: &str, cap| -> io::Result<Vec<u8>> {
        let response = client
            .get(url)
            .call()
            .map_err(|_| fail("GitHub update request failed; existing HC kept"))?;
        bounded(response.into_reader(), cap)
    };
    let current = Version::parse(VERSION).map_err(|_| fail("invalid current version"))?;
    let Some(release) = select_release(&fetch(RELEASES, 4 * 1024 * 1024)?, &current, asset()?)?
    else {
        if !background {
            println!("HC {VERSION} is up to date.");
        }
        return Ok(());
    };
    if option == "--check" {
        println!(
            "HC {} available (installed {VERSION}). Run hc update to install.",
            release.tag_name
        );
        return Ok(());
    }
    let name = asset()?;
    let base = format!("{REPO}/releases/download/{}", release.tag_name);
    let checksums = fetch(&format!("{base}/SHA256SUMS"), 64 * 1024)?;
    let binary = fetch(&format!("{base}/{name}"), MAX_BINARY)?;
    verify_checksum(&binary, &checksums, name)?;
    let stage = tempfile::tempdir_in(exe.parent().unwrap())?;
    let candidate = stage
        .path()
        .join(if cfg!(windows) { "hc.exe" } else { "hc" });
    fs::write(&candidate, binary)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755))?;
    }
    verify_version(&candidate, &release.tag_name[1..])?;
    // Don't overwrite an independently installed binary, or an opt-out during download.
    if digest(&fs::read(&exe)?) != original || (background && !enabled(&exe)) {
        return Err(fail(
            "HC installation changed during download; update skipped",
        ));
    }
    replace(&exe, &candidate)?;
    if !background {
        println!(
            "Updated HC to {}. New launches use this version; running sessions continue unchanged.",
            release.tag_name
        );
    }
    Ok(())
}

fn replace(exe: &Path, candidate: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        // Windows must move a running executable aside. Keep a separate closed
        // rollback copy before attempting that operation, including on disk-full errors.
        let backup = tempfile::NamedTempFile::new_in(exe.parent().unwrap())?.into_temp_path();
        fs::copy(exe, &backup)?;
        if let Err(error) = self_replace::self_replace(candidate) {
            if !exe.exists() {
                fs::rename(&backup, exe)?;
            }
            return Err(error);
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = exe;
        self_replace::self_replace(candidate)
    }
}

fn bounded(reader: impl Read, cap: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(fail("HC update exceeds size limit"));
    }
    Ok(bytes)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn verify_checksum(binary: &[u8], checksums: &[u8], asset: &str) -> io::Result<()> {
    let sums = std::str::from_utf8(checksums).map_err(|_| fail("invalid release checksums"))?;
    let matches: Vec<_> = sums
        .lines()
        .filter_map(|line| {
            let parts: Vec<_> = line.split_whitespace().collect();
            (parts.len() == 2 && parts[1] == asset).then(|| parts[0])
        })
        .collect();
    if matches.len() != 1 || matches[0] != digest(binary) {
        return Err(fail(
            "HC release checksum mismatch or missing; existing HC kept",
        ));
    }
    Ok(())
}

fn verify_version(candidate: &Path, version: &str) -> io::Result<()> {
    // A bounded child avoids hanging the updater on an incompatible payload.
    let output = tempfile::tempfile()?;
    let mut child = Command::new(candidate)
        .arg("--version")
        .env("HC_AUTO_UPDATE", "0")
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(Stdio::null())
        .spawn()?;
    for _ in 0..100 {
        if let Some(status) = child.try_wait()? {
            let mut output = output;
            output.rewind()?;
            let bytes = bounded(output, 1024)?;
            return if status.success() && bytes == format!("hc {version}\n").as_bytes() {
                Ok(())
            } else {
                Err(fail("downloaded HC version check failed; existing HC kept"))
            };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    Err(fail(
        "downloaded HC version check timed out; existing HC kept",
    ))
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    name: String,
}

fn select_release(bytes: &[u8], current: &Version, asset: &str) -> io::Result<Option<Release>> {
    let releases: Vec<Release> =
        serde_json::from_slice(bytes).map_err(|_| fail("invalid GitHub release metadata"))?;
    Ok(releases
        .into_iter()
        .filter_map(|r| {
            let version = Version::parse(r.tag_name.strip_prefix('v')?).ok()?;
            let stable = !r.prerelease && version.pre.is_empty();
            if r.draft
                || version <= *current
                || (current.pre.is_empty() && !stable)
                || !version.build.is_empty()
                || !r.assets.iter().any(|a| a.name == asset)
                || !r.assets.iter().any(|a| a.name == "SHA256SUMS")
            {
                return None;
            }
            Some((version, r))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, r)| r))
}

fn asset() -> io::Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("hc-aarch64-apple-darwin"),
        ("macos", "x86_64") => Ok("hc-x86_64-apple-darwin"),
        ("linux", "aarch64") => Ok("hc-aarch64-unknown-linux-gnu"),
        ("linux", "x86_64") => Ok("hc-x86_64-unknown-linux-gnu"),
        ("windows", "x86_64") => Ok("hc-x86_64-pc-windows-msvc.exe"),
        _ => Err(fail("no published HC update for this platform")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str) -> serde_json::Value {
        serde_json::json!({"tag_name":format!("v{version}"),"draft":false,"prerelease":version.contains('-'),"assets":[{"name":"native"},{"name":"SHA256SUMS"}]})
    }

    #[test]
    fn semver_channels_incomplete_and_rollback() {
        let mut incomplete = release("9.0.0");
        incomplete["assets"] = serde_json::json!([]);
        let mut draft = release("8.0.0");
        draft["draft"] = true.into();
        let bytes = serde_json::to_vec(&vec![
            release("0.1.0-alpha.9"),
            release("0.1.0-alpha.10"),
            release("0.1.0-alpha.6"),
            incomplete,
            draft,
        ])
        .unwrap();
        assert_eq!(
            select_release(&bytes, &Version::parse("0.1.0-alpha.6").unwrap(), "native")
                .unwrap()
                .unwrap()
                .tag_name,
            "v0.1.0-alpha.10"
        );
        assert!(
            select_release(&bytes, &Version::parse("0.1.0").unwrap(), "native")
                .unwrap()
                .is_none()
        );
        let bytes = serde_json::to_vec(&vec![release("0.1.0"), release("0.2.0-alpha.1")]).unwrap();
        assert_eq!(
            select_release(&bytes, &Version::parse("0.0.9").unwrap(), "native")
                .unwrap()
                .unwrap()
                .tag_name,
            "v0.1.0"
        );
        assert!(select_release(b"not json", &Version::new(0, 1, 0), "native").is_err());
    }

    #[test]
    fn integrity_missing_duplicate_and_size_limits() {
        let sum = format!("{}  native\n", digest(b"payload"));
        assert!(verify_checksum(b"payload", sum.as_bytes(), "native").is_ok());
        assert!(verify_checksum(b"tampered", sum.as_bytes(), "native").is_err());
        assert!(verify_checksum(b"payload", sum.repeat(2).as_bytes(), "native").is_err());
        assert!(verify_checksum(b"payload", sum.as_bytes(), "other").is_err());
        assert!(bounded(&b"four"[..], 3).is_err());
        assert_eq!(bounded(&b"four"[..], 4).unwrap(), b"four");
    }

    #[test]
    fn throttling_and_process_lock() {
        assert!(due(0, 1));
        assert!(!due(100, 101));
        assert!(due(100, 100 + INTERVAL));
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("hc");
        let first = lock(&exe).unwrap();
        assert!(lock(&exe).is_err());
        drop(first);
        assert!(lock(&exe).is_ok());
    }

    #[test]
    fn native_replacement_in_isolated_child() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join(if cfg!(windows) { "hc.exe" } else { "hc" });
        fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        let candidate = dir.path().join("candidate");
        fs::write(&candidate, b"replacement payload").unwrap();
        let status = Command::new(&exe)
            .args(["--exact", "updater::tests::replacement_child", "--ignored"])
            .env("HC_REPLACE_TEST", &candidate)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(fs::read(exe).unwrap(), b"replacement payload");
    }

    #[test]
    #[ignore = "invoked only in a copied subprocess by native_replacement_in_isolated_child"]
    fn replacement_child() {
        let candidate = PathBuf::from(std::env::var_os("HC_REPLACE_TEST").unwrap());
        replace(&std::env::current_exe().unwrap(), &candidate).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_lock_is_rejected_and_version_is_checked() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("hc");
        let other = dir.path().join("other");
        fs::write(&other, b"keep").unwrap();
        symlink(&other, sibling(&exe, ".hc-update.lock")).unwrap();
        assert!(lock(&exe).is_err());
        assert_eq!(fs::read(&other).unwrap(), b"keep");
        fs::write(&exe, b"#!/bin/sh\nprintf 'hc 0.1.0\\n'\n").unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(verify_version(&exe, "0.1.0").is_ok());
        assert!(verify_version(&exe, "0.2.0").is_err());
    }
}
