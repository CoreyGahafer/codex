#![cfg(unix)]
use codex_client::HttpTransport;
use codex_client::Request;
use codex_client::RequestCompression;
use codex_client::ReqwestTransport;
use codex_client::TransportError;
use http::Method;
use serde_json::json;
use std::io::Read;
use std::io::Write;
use std::time::Duration;
#[cfg(unix)]
fn executable_guard(
    directory: &std::path::Path,
    script: &str,
) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = directory.join("guard");
    std::fs::write(&path, script)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

#[cfg(unix)]
#[tokio::test]
async fn request_guard_retains_ambiguous_spend_and_reserves_each_attempt() {
    let directory = tempfile::tempdir().unwrap();
    let ledger = directory.path().join("ledger.sqlite");
    let metadata = directory.path().join("metadata.jsonl");
    let guard_result = executable_guard(
        directory.path(),
        &format!(
            r#"#!/usr/bin/python3
import json, sqlite3, sys
request = json.load(sys.stdin)
with open({metadata:?}, 'a') as log:
    log.write(json.dumps(request) + '\n')
with sqlite3.connect({ledger:?}) as db:
    db.execute('CREATE TABLE IF NOT EXISTS reservations (id TEXT PRIMARY KEY, maximum INTEGER, actual INTEGER)')
    db.execute('BEGIN IMMEDIATE')
    result = db.execute('INSERT INTO reservations SELECT ?,15000000,NULL WHERE (SELECT COALESCE(SUM(COALESCE(actual,maximum)),0) FROM reservations)+15000000<=25000000', (request['request_id'],))
    approved = result.rowcount == 1
sys.exit(0 if approved else 1)
"#
        ),
    );
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut data = [0; 8192];
        let _ = stream.read(&mut data).unwrap();
        stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        listener
    });
    let transport = ReqwestTransport::new(
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    )
    .with_request_guard(guard_result.unwrap());
    let request = Request::new(Method::POST, format!("http://{address}/v1/responses?token=secret"))
        .with_json(&json!({"model":"fixture", "input":"private prompt", "max_output_tokens":100, "tools":[{"type":"function"}]}))
        .with_compression(RequestCompression::Zstd)
        .into_prepared().unwrap();
    let result = codex_client::run_with_retry(
        codex_client::RetryPolicy {
            max_attempts: 3,
            base_delay: Duration::ZERO,
            retry_on: codex_client::RetryOn {
                retry_429: true,
                retry_5xx: true,
                retry_transport: true,
            },
        },
        || request.clone(),
        |request, _| transport.execute(request),
    )
    .await;
    assert!(matches!(result, Err(TransportError::Build(_))));
    let listener = server.join().unwrap();
    listener.set_nonblocking(true).unwrap();
    assert!(
        matches!(listener.accept(), Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
    );
    let lines = std::fs::read_to_string(metadata).unwrap();
    let rows = lines
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0]["request_id"], rows[1]["request_id"]);
    assert_eq!(rows[0]["model"], "fixture");
    assert_eq!(rows[0]["max_output_tokens"], 100);
    assert_eq!(rows[0]["tool_types"], json!(["function"]));
    assert!(!lines.contains("private prompt"));
    assert!(!lines.contains("secret"));
}
