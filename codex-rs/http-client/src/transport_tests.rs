use super::*;
use serde_json::json;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;

#[tokio::test]
async fn enabled_request_logging_emits_transport_url_and_body() {
    let logs = capture_transport_logs(HttpClient::new(test_reqwest_client())).await;

    assert!(logs.contains("log capture sentinel"));
    assert!(logs.contains("url-secret"));
    assert!(logs.contains("body-secret"));
}

#[tokio::test]
async fn disabled_request_logging_suppresses_transport_url_and_body() {
    let logs =
        capture_transport_logs(HttpClient::new(test_reqwest_client()).without_request_logging())
            .await;

    assert!(logs.contains("log capture sentinel"));
    assert!(!logs.contains("url-secret"));
    assert!(!logs.contains("body-secret"));

    let controller = crate::NetworkPolicyController::default();
    let policy = controller.policy();
    controller.publish(policy.revision(), crate::DestinationPolicy::Unrestricted);
    let factory = crate::HttpClientFactory::new(crate::OutboundProxyPolicy::ReqwestDefault)
        .with_network_policy(policy);
    let client =
        crate::RouteAwareClientPool::new(factory, crate::ClientRouteClass::Api).into_client();
    let logs = capture_transport_logs(client.clone()).await;
    assert!(logs.contains("url-secret"));
    let logs = capture_transport_logs(client.clone().without_request_logging()).await;
    assert!(!logs.contains("url-secret"), "{logs}");
    assert!(!logs.contains("body-secret"));
    assert!(capture_transport_logs(client).await.contains("url-secret"));
}

#[tokio::test]
async fn connection_failures_are_classified_without_exposing_request_urls() {
    let unavailable_server =
        std::net::TcpListener::bind(("127.0.0.1", 0)).expect("server port should bind");
    let server_addr = unavailable_server
        .local_addr()
        .expect("server listener should have an address");
    drop(unavailable_server);
    let transport = ReqwestTransport::from_http_client(HttpClient::new(test_reqwest_client()));
    let request = Request::new(
        Method::POST,
        format!("http://{server_addr}/responses?token=url-secret"),
    );

    let error = match transport.stream(request).await {
        Err(TransportError::Connection(error)) => error,
        Err(error) => panic!("expected a connection failure, got {error}"),
        Ok(_) => panic!("an unavailable server should not return a response"),
    };
    assert!(!error.to_string().contains("url-secret"));
}

fn test_reqwest_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("HTTP client should build")
}

async fn capture_transport_logs(client: HttpClient) -> String {
    let unavailable_server =
        std::net::TcpListener::bind(("127.0.0.1", 0)).expect("server port should bind");
    let server_addr = unavailable_server
        .local_addr()
        .expect("server listener should have an address");
    drop(unavailable_server);
    let transport = ReqwestTransport::from_http_client(client);
    let log_buffer = Arc::new(Mutex::new(Vec::new()));
    let writer_buffer = Arc::clone(&log_buffer);
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(move || TestLogWriter(Arc::clone(&writer_buffer)))
            .with_filter(
                tracing_subscriber::filter::Targets::new()
                    .with_target("codex_http_client::transport", tracing::Level::TRACE)
                    .with_target("codex_http_client::client", tracing::Level::DEBUG),
            ),
    );
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::trace!(target: "codex_http_client::transport", "log capture sentinel");
    let mut request = Request::new(
        Method::POST,
        format!("http://{server_addr}/request?token=url-secret"),
    )
    .with_json(&json!({"token": "body-secret"}));
    request.timeout = Some(Duration::from_secs(1));

    let _ = transport.execute(request).await;

    String::from_utf8(
        log_buffer
            .lock()
            .expect("log buffer should not be poisoned")
            .clone(),
    )
    .expect("captured logs should be UTF-8")
}

#[derive(Clone)]
struct TestLogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for TestLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("log buffer should not be poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
#[tokio::test]
async fn request_guard_denies_before_http_dispatch() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let guard = directory.path().join("deny");
    std::fs::write(&guard, "#!/bin/sh\nexit 1\n").unwrap();
    std::fs::set_permissions(&guard, std::fs::Permissions::from_mode(0o700)).unwrap();
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    for guard in [
        guard,
        directory.path().join("missing"),
        std::path::PathBuf::from("relative-guard"),
    ] {
        for streaming in [false, true] {
            let transport =
                ReqwestTransport::new(test_reqwest_client()).with_request_guard(guard.clone());
            let mut request = Request::new(
                Method::POST,
                format!("http://{}/v1/responses", listener.local_addr().unwrap()),
            );
            request.timeout = Some(Duration::from_millis(100));
            let error = if streaming {
                transport.stream(request).await.err()
            } else {
                transport.execute(request).await.err()
            }
            .expect("guard must deny");
            assert!(
                error.to_string().contains("request budget guard"),
                "{error}"
            );
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
        }
    }
}

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
async fn request_guard_cancellation_and_timeout_kill_the_guard_without_dispatch() {
    use tokio::io::AsyncReadExt;
    for timeout in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("ready.sock");
        let ready = tokio::net::UnixListener::bind(&socket).unwrap();
        let guard_result = executable_guard(
            directory.path(),
            &format!(
                r#"#!/usr/bin/python3
import json, socket, sys
json.load(sys.stdin)
s = socket.socket(socket.AF_UNIX)
s.connect({socket:?})
s.sendall(b'S')
s.recv(1)
"#
            ),
        );
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let transport =
            ReqwestTransport::new(test_reqwest_client()).with_request_guard(guard_result.unwrap());
        let request = Request::new(
            Method::POST,
            format!("http://{}/v1/responses", listener.local_addr().unwrap()),
        );
        let task = tokio::spawn(async move { transport.execute(request).await });
        let (mut connected, _) = ready.accept().await.unwrap();
        assert_eq!(connected.read_u8().await.unwrap(), b'S');
        if timeout {
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(5)).await;
            assert!(matches!(task.await.unwrap(), Err(TransportError::Build(_))));
            tokio::time::resume();
        } else {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        assert_eq!(connected.read_to_end(&mut Vec::new()).await.unwrap(), 0);
        assert!(
            matches!(listener.accept(), Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
        );
    }
}
