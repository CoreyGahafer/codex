use crate::Request;
use crate::TransportError;
use serde_json::json;
use std::io::Read;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub(crate) async fn authorize(executable: &Path, request: &Request) -> Result<(), TransportError> {
    let denied = || TransportError::Build("request budget guard failed or denied dispatch".into());
    if !executable.is_absolute() {
        return Err(denied());
    }
    let url = url::Url::parse(&request.url).map_err(|_| denied())?;
    let prepared = request.prepare_body_for_send().map_err(|_| denied())?;
    let body = prepared.body.unwrap_or_default();
    let mut reader: Box<dyn Read + Send> =
        match prepared.headers.get(http::header::CONTENT_ENCODING) {
            Some(encoding) if encoding == "zstd" => Box::new(
                zstd::stream::read::Decoder::new(std::io::Cursor::new(&body))
                    .map_err(|_| denied())?,
            ),
            Some(_) => return Err(denied()),
            None => Box::new(std::io::Cursor::new(&body)),
        };
    let mut json_bytes = Vec::new();
    reader
        .by_ref()
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut json_bytes)
        .map_err(|_| denied())?;
    if json_bytes.len() > 16 * 1024 * 1024 {
        return Err(denied());
    }
    let metadata: serde_json::Value = if json_bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&json_bytes).map_err(|_| denied())?
    };
    let input = serde_json::to_vec(&json!({
        "protocol_version": 1,
        "request_id": uuid::Uuid::new_v4().to_string(),
        "method": request.method.as_str(),
        "origin": url.origin().ascii_serialization(),
        "path": url.path(),
        "model": metadata.get("model"),
        "max_output_tokens": metadata.get("max_output_tokens"),
        "tool_types": metadata.get("tools").and_then(|tools| tools.as_array()).map(|tools| tools.iter().map(|tool| tool.get("type").cloned().unwrap_or(serde_json::Value::Null)).collect::<Vec<_>>()),
        "body_bytes": json_bytes.len(),
    })).map_err(|_| denied())?;
    let decision = async {
        let mut child = Command::new(executable)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("missing guard input"))?;
        stdin.write_all(&input).await?;
        drop(stdin);
        child.wait().await
    };
    match tokio::time::timeout(Duration::from_secs(5), decision).await {
        Ok(Ok(status)) if status.success() => Ok(()),
        _ => Err(denied()),
    }
}
