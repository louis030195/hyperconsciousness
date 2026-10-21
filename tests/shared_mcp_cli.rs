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
    assert_eq!(value["error"]["code"], -32004);
    assert_eq!(value["error"]["message"], "not signed in; run hc login");
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

fn node_client(root: &Path, address: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hc"));
    command
        .env("HC_CONFIG_DIR", root.join("client"))
        .env("HOME", root.join("small-device"))
        .env_remove("HC_DIR")
        .env_remove("BRAINMESH_DIR")
        .env("BRAINMESH_NO_KEYSTORE", "1");
    let credential = root.join("node-credential.json");
    hyperconsciousness::durable::write_private(
        &credential,
        &serde_json::to_vec(&json!({
            "endpoint":format!("http://{address}"), "access_token":TOKEN
        }))
        .unwrap(),
    )
    .unwrap();
    let profile = root.join("node.json");
    fs::write(
        &profile,
        serde_json::to_vec(&json!({
            "version":1, "origin":format!("http://{address}"), "routePrefix":"",
            "credentialFile":credential, "defaultReader":true
        }))
        .unwrap(),
    )
    .unwrap();
    let mut setup = Command::new(env!("CARGO_BIN_EXE_hc"));
    let result = setup
        .args(["setup"])
        .arg(profile)
        .env("HC_CONFIG_DIR", root.join("client"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains(TOKEN));
    command
}

fn client_rpc(command: &mut Command, request: &Value) -> Value {
    if command.get_args().len() == 0 {
        command.arg("mcp");
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{request}").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn small_node_uses_the_same_search_and_record_without_replication() {
    let root = tempfile::tempdir().unwrap();
    let brain = root.path().join("brain");
    let grant = fixture(&brain);
    let server = start(
        &["mcp", "--as", &grant, "--dir", brain.to_str().unwrap()],
        root.path(),
    );
    let search = json!({"jsonrpc":"2.0","id":42,"method":"tools/call",
        "params":{"name":"search","arguments":{"query":"canary","format":"structured","limit":1}}});
    let remote = client_rpc(&mut node_client(root.path(), &server.1), &search);
    assert_eq!(remote["id"], 42);
    assert_eq!(
        remote["result"]["structuredContent"]["schema"],
        "hc.context.v1"
    );
    assert_eq!(
        remote["result"]["structuredContent"]["items"][0]["text"],
        "visible-canary"
    );
    assert!(!remote.to_string().contains("hidden-canary"));
    let reference = remote["result"]["structuredContent"]["items"][0]["ref"].clone();
    let record = json!({"jsonrpc":"2.0","id":"open","method":"tools/call",
        "params":{"name":"record","arguments":{"ref":reference,"format":"structured"}}});
    let remote_record = client_rpc(&mut node_client(root.path(), &server.1), &record);
    assert_eq!(remote_record["id"], "open");
    assert_eq!(
        remote_record["result"]["structuredContent"]["items"][0]["text"],
        "visible-canary"
    );
    let (status, direct) = request(&server.1, "POST", "/mcp", &auth(), &record.to_string());
    assert_eq!(status, 200);
    let direct: Value = serde_json::from_str(&direct).unwrap();
    assert_eq!(
        remote_record["result"]["structuredContent"]["items"],
        direct["result"]["structuredContent"]["items"]
    );
    let found = node_client(root.path(), &server.1)
        .args(["find", "canary", "--scope", "hc"])
        .output()
        .unwrap();
    assert!(
        found.status.success(),
        "{}",
        String::from_utf8_lossy(&found.stderr)
    );
    let found = String::from_utf8(found.stdout).unwrap();
    assert!(
        found.contains("hc  ") && found.contains("visible-canary"),
        "{found}"
    );
    assert!(!found.contains("hidden-canary"));
    assert!(!root.path().join("small-device/.brain").exists());
    assert!(!root.path().join("client/session.json").exists());
    let ranked = client_rpc(
        &mut node_client(root.path(), &server.1),
        &json!({
            "jsonrpc":"2.0", "id":43, "method":"tools/call", "params":{"name":"search", "arguments":{
                "query":"visible canary", "mode":"relevance", "match_terms":"all", "format":"structured"
            }}
        }),
    );
    assert_eq!(ranked["result"]["structuredContent"]["order"], "relevance");
    assert_eq!(
        ranked["result"]["structuredContent"]["items"][0]["ref"],
        reference
    );
    let write = client_rpc(
        &mut node_client(root.path(), &server.1),
        &json!({
            "jsonrpc":"2.0", "id":44, "method":"tools/call", "params":{"name":"remember", "arguments":{"text":"must not write"}}
        }),
    );
    assert!(write["result"]["isError"] == true || write.get("error").is_some());
    let status = node_client(root.path(), &server.1)
        .args(["status", "--remote"])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    // Exact local grants remain local even with a remote default configured.
    let local = client_rpc(
        node_client(root.path(), &server.1).args([
            "mcp",
            "--as",
            &grant,
            "--dir",
            brain.to_str().unwrap(),
        ]),
        &search,
    );
    assert_eq!(
        local["result"]["structuredContent"]["items"],
        remote["result"]["structuredContent"]["items"]
    );
}

#[test]
fn unavailable_or_denied_node_never_becomes_empty_results_or_local_fallback() {
    let root = tempfile::tempdir().unwrap();
    let brain = root.path().join("brain");
    let grant = fixture(&brain);
    let mut server = start(
        &["mcp", "--as", &grant, "--dir", brain.to_str().unwrap()],
        root.path(),
    );
    let query = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"search","arguments":{"query":"canary"}}});
    let mut client = node_client(root.path(), &server.1);
    hyperconsciousness::durable::write_private(&root.path().join("node-credential.json"), &serde_json::to_vec(&json!({
        "endpoint":format!("http://{}",server.1),"access_token":"incorrect-but-well-formed-synthetic-token"
    })).unwrap()).unwrap();
    let denied = client_rpc(&mut client, &query);
    assert_eq!(denied["error"]["code"], -32001);
    assert!(denied.get("result").is_none());
    // Server-side grant revocation applies even to a previously successful client.
    let revoked = Command::new(env!("CARGO_BIN_EXE_hc"))
        .args(["revoke", &grant, "--dir", brain.to_str().unwrap()])
        .env("BRAINMESH_NO_KEYSTORE", "1")
        .output()
        .unwrap();
    assert!(
        revoked.status.success(),
        "{}",
        String::from_utf8_lossy(&revoked.stderr)
    );
    let revoked = client_rpc(&mut node_client(root.path(), &server.1), &query);
    assert!(
        revoked["result"]["isError"] == true || revoked.get("error").is_some(),
        "{revoked}"
    );
    assert!(!revoked.to_string().contains("visible-canary"));
    server.0.kill().unwrap();
    server.0.wait().unwrap();
    let offline = client_rpc(&mut node_client(root.path(), &server.1), &query);
    assert_eq!(offline["error"]["code"], -32002);
    let offline_find = node_client(root.path(), &server.1)
        .args(["find", "canary", "--scope", "hc"])
        .output()
        .unwrap();
    assert!(!offline_find.status.success());
    assert!(!String::from_utf8_lossy(&offline_find.stdout).contains("nothing matched"));
    assert!(!root.path().join("small-device/.brain").exists());
    let local_skills = node_client(root.path(), &server.1)
        .args(["find", "nothing-synthetic", "--scope", "skills"])
        .output()
        .unwrap();
    assert!(local_skills.status.success());
    let conflict = node_client(root.path(), &server.1)
        .args(["find", "canary", "--remote", "--local"])
        .output()
        .unwrap();
    assert!(!conflict.status.success());
}

#[test]
fn node_client_rejects_wrong_rpc_ids_redirects_and_rate_limits_without_leaking_bodies() {
    for (status, body, expected) in [
        (
            200,
            r#"{"jsonrpc":"2.0","id":999,"result":{"private":"must not escape"}}"#,
            -32000,
        ),
        (429, "private upstream body", -32003),
        (302, "private redirect body", -32000),
        (200, "not json private body", -32000),
    ] {
        let root = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let response = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut input = BufReader::new(stream.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                input.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            let mut bytes = vec![0; length];
            input.read_exact(&mut bytes).unwrap();
            write!(stream,"HTTP/1.1 {status} Test\r\nLocation: http://127.0.0.1:1/stolen\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        });
        let request = json!({"jsonrpc":"2.0","id":1,"method":"ping"});
        let reply = client_rpc(&mut node_client(root.path(), &address), &request);
        assert_eq!(reply["error"]["code"], expected, "{reply}");
        assert!(!reply.to_string().contains("private"));
        assert!(!reply.to_string().contains(TOKEN));
        response.join().unwrap();
    }
}

#[test]
fn hosted_find_uses_advertised_schema_and_preserves_text_references() {
    let root = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        for index in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut input = BufReader::new(stream.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                input.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            let mut bytes = vec![0; length];
            input.read_exact(&mut bytes).unwrap();
            let message: Value = serde_json::from_slice(&bytes).unwrap();
            let result = if index == 0 {
                assert_eq!(message["method"], "tools/list");
                json!({"tools":[{"name":"search","inputSchema":{"type":"object","additionalProperties":false,"properties":{"query":{"type":"string"},"limit":{"type":"number"}}}}]})
            } else {
                assert_eq!(
                    message["params"]["arguments"],
                    json!({"query":"canary","limit":2})
                );
                json!({"content":[{"type":"text","text":"2026-10-14  [abcd1234:2]  visible-canary\nnext_cursor: opaque-cursor"}]})
            };
            let body = json!({"jsonrpc":"2.0","id":message["id"],"result":result}).to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    let found = node_client(root.path(), &address)
        .args(["find", "canary", "--scope", "hc", "--limit", "2"])
        .output()
        .unwrap();
    assert!(
        found.status.success(),
        "{}",
        String::from_utf8_lossy(&found.stderr)
    );
    assert_eq!(
        String::from_utf8(found.stdout).unwrap(),
        "2026-10-14  [abcd1234:2]  visible-canary\nnext_cursor: opaque-cursor\n"
    );
    server.join().unwrap();
    assert!(!root.path().join("small-device/.brain").exists());
}
