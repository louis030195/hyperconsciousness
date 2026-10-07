// screenpipe — AI that knows everything you've seen, said, or heard
// https://screenpipe.com

use hyperconsciousness::grant::{NORMAL, READ, SECRET};
use hyperconsciousness::keyring::{DataKeys, RuntimeKeys};
use hyperconsciousness::{Clock, Grant, Identity, Record, Scope, Store};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const TOKEN: &str = "synthetic-test-token-00000000000000000000000000000000";
struct Server(Child, String);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn token(root: &Path) -> std::path::PathBuf {
    let path = root.join("http-token");
    fs::write(&path, TOKEN).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}
fn start(args: &[&str], root: &Path) -> Server {
    let token = token(root);
    let mut child = Command::new(env!("CARGO_BIN_EXE_hc"))
        .args(args)
        .args(["--bind", "127.0.0.1:0", "--token-file"])
        .arg(token)
        .env("HC_CONFIG_DIR", root.join("access"))
        .env("HC_DIR", root.join("unused-personal"))
        .env("BRAINMESH_NO_KEYSTORE", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut server = Server(child, String::new());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send((result, line));
    });
    let (result, line) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("server startup deadline");
    result.unwrap();
    assert!(line.starts_with("MCP listening on http://"), "{line}");
    assert!(!line.contains(TOKEN));
    server.1 = line
        .trim()
        .strip_prefix("MCP listening on http://")
        .unwrap()
        .strip_suffix("/mcp")
        .unwrap()
        .to_owned();
    server
}
fn request(address: &str, method: &str, path: &str, headers: &str, body: &str) -> (u16, String) {
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        socket,
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\n{headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        body.to_owned(),
    )
}
fn auth() -> String {
    format!("Authorization: Bearer {TOKEN}\r\n")
}
fn fixture(root: &Path) -> String {
    std::env::set_var("BRAINMESH_NO_KEYSTORE", "1");
    let mut identity = Identity::load_or_create(root).unwrap();
    identity.create_brain().unwrap();
    let keys = RuntimeKeys::open(root, &identity).unwrap();
    let grant = Grant::issue(
        &identity.grant_authority_signing().unwrap(),
        identity.device(),
        Scope {
            max_sensitivity: NORMAL,
            ..Scope::default()
        },
        READ,
        u64::MAX,
    )
    .unwrap();
    let blob: String = grant.encode().iter().map(|b| format!("{b:02x}")).collect();
    let store = Store::open(root).unwrap();
    let log = store.log_for_write(identity.device()).unwrap();
    let mut cursor = log.cache_head().unwrap();
    for payload in [
        json!({"kind":"grant","id":grant.id().hex(),"blob":blob,"sensitivity":SECRET}),
        json!({"kind":"note","text":"visible-canary","sensitivity":NORMAL}),
        json!({"kind":"note","text":"hidden-canary","sensitivity":SECRET}),
    ] {
        let record = Record::create(
            &identity.signing,
            if cursor.empty { 0 } else { cursor.seq + 1 },
            cursor.id,
            Clock::new().now(),
            keys.current_epoch(),
            keys.current_key().unwrap(),
            payload.to_string().as_bytes(),
        )
        .unwrap();
        log.append_new_batch(&[record], &mut cursor).unwrap();
    }
    grant.id().hex()
}
#[test]
fn many_clients_share_one_scoped_server_and_disconnect_without_stopping_it() {
    let root = tempfile::tempdir().unwrap();
    let brain = root.path().join("brain");
    let grant = fixture(&brain);
    let mut server = start(
        &["mcp", "--as", &grant, "--dir", brain.to_str().unwrap()],
        root.path(),
    );
    let pid = server.0.id();
    let clients: Vec<_> = (0..24)
        .map(|id| {
            let address = server.1.clone();
            std::thread::spawn(move || {
                let body = json!({"jsonrpc":"2.0","id":id,"method":"initialize"}).to_string();
                let (status, reply) = request(&address, "POST", "/mcp", &auth(), &body);
                assert_eq!(status, 200);
                let reply: Value = serde_json::from_str(&reply).unwrap();
                assert_eq!(reply["id"], id);
                assert!(reply.get("result").is_some());
            })
        })
        .collect();
    for client in clients {
        client.join().unwrap();
    }
    assert!(server.0.try_wait().unwrap().is_none());
    assert_eq!(server.0.id(), pid);
    let query=json!({"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"search","arguments":{"query":"canary"}}}).to_string();
    let (status, reply) = request(&server.1, "POST", "/mcp", &auth(), &query);
    assert_eq!(status, 200);
    assert!(reply.contains("visible-canary"), "{reply}");
    assert!(!reply.contains("hidden-canary"));
    assert_eq!(
        request(
            &server.1,
            "POST",
            "/mcp",
            &auth(),
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#
        )
        .0,
        202
    );
    assert_eq!(request(&server.1, "DELETE", "/mcp", &auth(), "").0, 204);
    assert_eq!(request(&server.1, "GET", "/health", &auth(), "").0, 200);
}
#[test]
fn shared_transport_rejects_unauthorized_browser_and_malformed_requests() {
    let root = tempfile::tempdir().unwrap();
    let brain = root.path().join("brain");
    let grant = fixture(&brain);
    let server = start(
        &["mcp", "--as", &grant, "--dir", brain.to_str().unwrap()],
        root.path(),
    );
    for headers in ["", "Authorization: Bearer wrong\r\n"] {
        assert_eq!(request(&server.1, "POST", "/mcp", headers, "{}").0, 401);
    }
    assert_eq!(
        request(
            &server.1,
            "POST",
            "/mcp",
            &format!("{}Origin: null\r\n", auth()),
            "{}"
        )
        .0,
        403
    );
    assert_eq!(
        request(
            &server.1,
            "POST",
            "/mcp",
            &format!("{}{}", auth(), auth()),
            "{}"
        )
        .0,
        400
    );
    for body in ["no json", "[]"] {
        assert_eq!(request(&server.1, "POST", "/mcp", &auth(), body).0, 400);
    }
    assert_eq!(request(&server.1, "GET", "/mcp", &auth(), "").0, 405);
}
#[test]
fn shared_remote_keeps_denied_reads_out_of_personal_brain() {
    let root = tempfile::tempdir().unwrap();
    let access = root.path().join("access");
    let profile = root.path().join("connection.json");
    fs::write(
        &profile,
        r#"{"version":1,"name":"test","origin":"https://example.test"}"#,
    )
    .unwrap();
    assert!(Command::new(env!("CARGO_BIN_EXE_hc"))
        .arg("setup")
        .arg(profile)
        .env("HC_CONFIG_DIR", &access)
        .output()
        .unwrap()
        .status
        .success());
    let server = start(&["mcp", "--remote"], root.path());
    let (status, reply) = request(
        &server.1,
        "POST",
        "/mcp",
        &auth(),
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
    );
    assert_eq!(status, 200);
    let value: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(value["error"]["code"], -32000);
    assert!(!root.path().join("unused-personal").exists());
    assert!(!access.join("session.json").exists());
}
#[test]
fn unsafe_bind_and_incomplete_options_fail_before_listening() {
    let root = tempfile::tempdir().unwrap();
    let brain = root.path().join("brain");
    let grant = fixture(&brain);
    let token = token(root.path());
    for options in [
        vec![
            "--bind",
            "0.0.0.0:0",
            "--token-file",
            token.to_str().unwrap(),
        ],
        vec!["--bind", "127.0.0.1:0"],
        vec!["--token-file", token.to_str().unwrap()],
        vec![
            "--bind",
            "127.0.0.1:0",
            "--bind",
            "127.0.0.1:0",
            "--token-file",
            token.to_str().unwrap(),
        ],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_hc"))
            .args(["mcp", "--as", &grant, "--dir", brain.to_str().unwrap()])
            .args(options)
            .env("BRAINMESH_NO_KEYSTORE", "1")
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stdout).contains(TOKEN));
        assert!(!String::from_utf8_lossy(&result.stderr).contains(TOKEN));
    }
}

#[cfg(unix)]
#[test]
fn shared_token_rejects_symlinks_and_world_readable_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = tempfile::tempdir().unwrap();
    let brain = root.path().join("brain");
    let grant = fixture(&brain);
    let token = token(root.path());
    let link = root.path().join("token-link");
    symlink(&token, &link).unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o644)).unwrap();
    for path in [&link, &token] {
        let result = Command::new(env!("CARGO_BIN_EXE_hc"))
            .args([
                "mcp",
                "--as",
                &grant,
                "--dir",
                brain.to_str().unwrap(),
                "--bind",
                "127.0.0.1:0",
                "--token-file",
            ])
            .arg(path)
            .env("BRAINMESH_NO_KEYSTORE", "1")
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stderr).contains(TOKEN));
    }
}
