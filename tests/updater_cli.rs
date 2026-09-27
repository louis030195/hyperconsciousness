// screenpipe — AI that knows everything you've seen, said, or heard
// https://screenpipe.com

use std::{
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn run(exe: &Path, args: &[&str], root: &Path) -> std::process::Output {
    Command::new(exe)
        .args(args)
        .env("HC_DIR", root.join("brain"))
        .env("HC_CONFIG_DIR", root.join("connection"))
        .env("HC_AUTO_UPDATE", "0")
        .output()
        .unwrap()
}

#[test]
fn update_controls_and_opt_out_leave_user_stores_untouched() {
    // Root-owned system binaries deliberately cannot self-update.
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let exe = root
        .path()
        .join(if cfg!(windows) { "hc.exe" } else { "hc" });
    fs::copy(env!("CARGO_BIN_EXE_hc"), &exe).unwrap();
    let original = fs::read(&exe).unwrap();
    for args in [&["--version"][..], &["update", "--help"]] {
        assert!(run(&exe, args, root.path()).status.success());
    }
    assert!(!root.path().join(".hc-update.lock").exists());
    assert!(run(&exe, &["update", "--enable"], root.path())
        .status
        .success());
    assert_eq!(
        fs::read(root.path().join(".hc-auto-update")).unwrap(),
        b"1\n"
    );
    assert!(run(&exe, &["__update"], root.path()).status.success());
    // An opted-out worker has not recorded or made a network attempt.
    assert_eq!(fs::read(root.path().join(".hc-update.lock")).unwrap(), b"");
    // A recently checked installation skips even with automatic updates enabled.
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    fs::write(root.path().join(".hc-update.lock"), &timestamp).unwrap();
    assert!(Command::new(&exe)
        .arg("__update")
        .env("HC_AUTO_UPDATE", "1")
        .status()
        .unwrap()
        .success());
    assert_eq!(
        fs::read_to_string(root.path().join(".hc-update.lock")).unwrap(),
        timestamp
    );
    assert!(run(&exe, &["update", "--disable"], root.path())
        .status
        .success());
    assert!(!root.path().join(".hc-auto-update").exists());
    assert!(!run(&exe, &["update", "--unknown"], root.path())
        .status
        .success());
    assert_eq!(fs::read(exe).unwrap(), original);
    assert!(!root.path().join("brain").exists());
    assert!(!root.path().join("connection").exists());
}
