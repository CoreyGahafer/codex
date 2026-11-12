use crate::Request;
use crate::TransportError;
use eventsource_stream::Eventsource;
use futures::StreamExt;
use serde_json::json;
use std::io::Read;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub(crate) struct Receipt {
    executable: std::path::PathBuf,
    request_id: String,
}

fn denied() -> TransportError {
    TransportError::Build("request budget guard failed or denied dispatch/settlement".into())
}

pub(crate) async fn authorize(
    executable: &Path,
    request: &Request,
) -> Result<Receipt, TransportError> {
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
    let receipt = Receipt {
        executable: executable.into(),
        request_id: uuid::Uuid::new_v4().to_string(),
    };
    receipt.call("reserve", json!({
        "method": request.method.as_str(),
        "origin": url.origin().ascii_serialization(),
        "path": url.path(),
        "model": metadata.get("model"),
        "max_output_tokens": metadata.get("max_output_tokens"),
        "service_tier": metadata.get("service_tier"),
        "tool_types": metadata.get("tools").and_then(|tools| tools.as_array()).map(|tools| tools.iter().map(|tool| tool.get("type").cloned().unwrap_or(serde_json::Value::Null)).collect::<Vec<_>>()),
        "body_bytes": json_bytes.len(),
        "cache_control_count": cache_control_count(&metadata),
    })).await?;
    Ok(receipt)
}

impl Receipt {
    async fn call(
        &self,
        operation: &str,
        mut payload: serde_json::Value,
    ) -> Result<(), TransportError> {
        payload["protocol_version"] = json!(2);
        payload["operation"] = json!(operation);
        payload["request_id"] = json!(self.request_id);
        let input = serde_json::to_vec(&payload).map_err(|_| denied())?;
        let decision = async {
            let mut child = Command::new(&self.executable)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| std::io::Error::other("missing guard input"))?;
            stdin.write_all(&input).await?;
            drop(stdin);
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| std::io::Error::other("missing guard acknowledgment"))?;
            let mut output = Vec::new();
            stdout.take(4097).read_to_end(&mut output).await?;
            if output.len() > 4096 {
                return Err(std::io::Error::other("oversized guard acknowledgment"));
            }
            let status = child.wait().await?;
            Ok::<_, std::io::Error>((status, output))
        };
        match tokio::time::timeout(Duration::from_secs(5), decision).await {
            Ok(Ok((status, output))) if status.success() => {
                let ack: serde_json::Value =
                    serde_json::from_slice(&output).map_err(|_| denied())?;
                if ack["protocol_version"] != 2
                    || ack["operation"] != operation
                    || ack["request_id"] != self.request_id
                {
                    return Err(denied());
                }
                Ok(())
            }
            _ => Err(denied()),
        }
    }

    pub(crate) async fn settle(&self, response: &serde_json::Value) -> Result<(), TransportError> {
        self.call(
            "settle",
            json!({"response": {
                "id": response.get("id"),
                "model": response.get("model"),
                "status": response.get("status"),
                "service_tier": response.get("service_tier"),
                "usage": response.get("usage"),
            }}),
        )
        .await
    }

    pub(crate) fn stream(self, bytes: crate::ByteStream) -> crate::ByteStream {
        Box::pin(async_stream::try_stream! {
            // Bound the SSE decoder's buffer even when the peer never terminates an event.
            let mut remaining = 16 * 1024 * 1024usize;
            let bounded = bytes.map(move |chunk| {
                let chunk = chunk?;
                remaining = remaining.checked_sub(chunk.len()).ok_or_else(denied)?;
                Ok::<_, TransportError>(chunk)
            });
            let mut events = bounded.eventsource();
            let mut settled = false;
            while let Some(event) = events.next().await {
                let event = event.map_err(|_| denied())?;
                let value: serde_json::Value = serde_json::from_str(&event.data).map_err(|_| denied())?;
                if matches!(value["type"].as_str(), Some("response.completed" | "response.incomplete" | "response.failed")) {
                    if settled { Err(denied())?; }
                    self.settle(&value["response"]).await?;
                    settled = true;
                }
                yield bytes::Bytes::from(format!("event: {}\ndata: {}\n\n", event.event, event.data.replace('\n', "\ndata: ")));
            }
            if !settled { Err(denied())?; }
        })
    }
}

fn cache_control_count(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(fields) => fields
            .iter()
            .map(|(key, value)| {
                usize::from(matches!(
                    key.as_str(),
                    "prompt_cache_options" | "prompt_cache_breakpoint" | "prompt_cache_retention"
                )) + cache_control_count(value)
            })
            .sum(),
        serde_json::Value::Array(values) => values.iter().map(cache_control_count).sum(),
        _ => 0,
    }
}
