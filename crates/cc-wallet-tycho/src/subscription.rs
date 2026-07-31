use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::{Client, Url};
use serde_json::{Value, json};

use crate::transport::{
    HttpClientConfig, build_http_client, canonicalize_endpoint, parse_jrpc_result_for_id,
    read_response_bytes_limited,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_SSE_EVENT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountUpdate {
    pub max_lt: u64,
    pub gen_utime: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionEvent {
    Ready { uuid: String },
    Update(AccountUpdate),
}

pub async fn account_subscription_loop(
    endpoint: String,
    address: String,
    mut emit: impl FnMut(SubscriptionEvent),
) -> Result<()> {
    let client = build_http_client(HttpClientConfig::streaming(
        Duration::from_secs(3),
        STREAM_READ_TIMEOUT,
    ))
    .context("failed to build SSE HTTP client")?;

    let stream_url = stream_url_for(&endpoint)?;

    let mut response = tokio::time::timeout(HANDSHAKE_TIMEOUT, client.get(stream_url).send())
        .await
        .map_err(|_| anyhow!("RPC subscription timed out"))?
        .map_err(|error| anyhow!("SSE stream request failed: {}", error.without_url()))?;
    if !response.status().is_success() {
        bail!("SSE stream returned HTTP {}", response.status());
    }

    let mut subscribed = false;
    let mut buffer = String::new();
    let mut last_dropped = 0;
    let mut last_account_update = None;

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| anyhow!("SSE stream read failed: {}", error.without_url()))?
    {
        buffer.push_str(&String::from_utf8_lossy(&chunk));
        while let Some((pos, sep_len)) = sse_event_end(&buffer) {
            if pos > MAX_SSE_EVENT_BYTES {
                bail!("SSE frame exceeded {MAX_SSE_EVENT_BYTES} bytes");
            }
            let raw = buffer[..pos].to_owned();
            buffer.drain(..pos + sep_len);
            let Some(event) = parse_sse_event(&raw) else {
                continue;
            };
            match event.name.as_str() {
                "uuid" => {
                    subscribe_account(&client, &endpoint, &event.data, &address).await?;
                    subscribed = true;
                    emit(SubscriptionEvent::Ready { uuid: event.data });
                }
                "update" | "keep-alive" if subscribed => {
                    if let Some(update) = parse_subscription_notification(
                        &event.name,
                        &event.data,
                        &mut last_dropped,
                        &mut last_account_update,
                    ) {
                        emit(SubscriptionEvent::Update(update));
                    }
                }
                _ => {}
            }
        }
        if buffer.len() > MAX_SSE_EVENT_BYTES {
            bail!("SSE frame exceeded {MAX_SSE_EVENT_BYTES} bytes without a terminator");
        }
    }

    bail!("RPC subscription stream closed")
}

fn stream_url_for(endpoint: &str) -> Result<Url> {
    let mut base = canonicalize_endpoint(endpoint)?;
    let query = base.query().map(str::to_owned);
    base.set_query(None);
    base.set_fragment(None);
    if !base.path().ends_with('/') {
        let dir = format!("{}/", base.path());
        base.set_path(&dir);
    }
    let mut stream = base
        .join("stream")
        .context("failed to build SSE stream URL")?;
    stream.set_query(query.as_deref());
    Ok(stream)
}

async fn subscribe_account(
    client: &Client,
    endpoint: &str,
    uuid: &str,
    address: &str,
) -> Result<()> {
    let mut url = canonicalize_endpoint(endpoint)?;
    if url.path().trim_matches('/').is_empty() {
        url.set_path("/");
    }
    let request = client.post(url).json(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "subSubscribe",
        "params": {
            "uuid": uuid,
            "addrs": [address],
        },
    }));
    let response = tokio::time::timeout(HANDSHAKE_TIMEOUT, request.send())
        .await
        .map_err(|_| anyhow!("RPC subscription timed out"))?
        .map_err(|error| anyhow!("subSubscribe request failed: {}", error.without_url()))?;
    if !response.status().is_success() {
        bail!("subSubscribe returned HTTP {}", response.status());
    }
    let bytes = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_response_bytes_limited(response))
        .await
        .map_err(|_| anyhow!("RPC subscription timed out"))?
        .context("subSubscribe response body was invalid")?;
    let value: Value =
        serde_json::from_slice(&bytes).context("subSubscribe response was not JSON")?;
    let _: Value = parse_jrpc_result_for_id(value, "subSubscribe", 1)?;
    Ok(())
}

struct SseEvent {
    name: String,
    data: String,
}

fn parse_sse_event(raw: &str) -> Option<SseEvent> {
    let mut name = None;
    let mut data = String::new();

    for line in raw.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(rest) = line.strip_prefix("event:") {
            name = Some(rest.trim_start().to_owned());
        } else if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.trim_start());
        }
    }

    Some(SseEvent { name: name?, data })
}

fn sse_event_end(buffer: &str) -> Option<(usize, usize)> {
    match (buffer.find("\r\n\r\n"), buffer.find("\n\n")) {
        (Some(crlf), Some(lf)) if lf < crlf => Some((lf, 2)),
        (Some(crlf), _) => Some((crlf, 4)),
        (None, Some(lf)) => Some((lf, 2)),
        (None, None) => None,
    }
}

fn parse_stream_update(data: &str) -> AccountUpdate {
    let Ok(value) = serde_json::from_str::<Value>(data) else {
        return AccountUpdate {
            max_lt: 0,
            gen_utime: None,
        };
    };
    let max_lt = json_u64_field(&value, "maxLt").unwrap_or(0);
    let gen_utime = json_u64_field(&value, "genUtime").and_then(|value| u32::try_from(value).ok());
    AccountUpdate { max_lt, gen_utime }
}

fn parse_subscription_notification(
    event_name: &str,
    data: &str,
    last_dropped: &mut u64,
    last_account_update: &mut Option<AccountUpdate>,
) -> Option<AccountUpdate> {
    match event_name {
        "update" => {
            let update = parse_stream_update(data);
            if let Some(dropped) = parse_stream_counter(data, "dropped") {
                *last_dropped = (*last_dropped).max(dropped);
            }
            *last_account_update = Some(update);
            Some(update)
        }
        "keep-alive" => {
            let dropped = parse_stream_counter(data, "dropped")?;
            if dropped <= *last_dropped {
                return None;
            }
            *last_dropped = dropped;
            Some(last_account_update.unwrap_or(AccountUpdate {
                max_lt: 0,
                gen_utime:
                    parse_stream_counter(data, "utime").and_then(|value| u32::try_from(value).ok()),
            }))
        }
        _ => None,
    }
}

fn parse_stream_counter(data: &str, field: &str) -> Option<u64> {
    let value = serde_json::from_str::<Value>(data).ok()?;
    json_u64_field(&value, field)
}

fn json_u64_field(value: &Value, field: &str) -> Option<u64> {
    match value.get(field)? {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_protocol_parity_vector() {
        assert_eq!(
            stream_url_for("https://host.example/rpc?token=kept")
                .unwrap()
                .as_str(),
            "https://host.example/rpc/stream?token=kept"
        );
        let raw = "event: update\r\ndata: {\"maxLt\":\"42\",\r\ndata: \"genUtime\":123}\r\n\r\n";
        let (end, separator_len) = sse_event_end(raw).unwrap();
        assert_eq!(separator_len, 4);
        let event = parse_sse_event(&raw[..end]).unwrap();
        assert_eq!(event.name, "update");
        assert_eq!(event.data, "{\"maxLt\":\"42\",\n\"genUtime\":123}");
        assert_eq!(
            parse_stream_update(&event.data),
            AccountUpdate {
                max_lt: 42,
                gen_utime: Some(123),
            }
        );
    }

    #[test]
    fn stream_url_preserves_a_path_based_endpoint_base() {
        assert_eq!(
            stream_url_for("https://rpc-testnet.tychoprotocol.com")
                .unwrap()
                .as_str(),
            "https://rpc-testnet.tychoprotocol.com/stream"
        );
        assert_eq!(
            stream_url_for("http://127.0.0.1:8001").unwrap().as_str(),
            "http://127.0.0.1:8001/stream"
        );
        assert_eq!(
            stream_url_for("https://host/rpc?apikey=secret&v=2")
                .unwrap()
                .as_str(),
            "https://host/rpc/stream?apikey=secret&v=2"
        );
        assert_eq!(
            stream_url_for("https://host/rpc").unwrap().as_str(),
            "https://host/rpc/stream"
        );
    }

    #[test]
    fn parses_uuid_and_update_events() {
        assert_eq!(
            parse_sse_event("event: uuid\ndata: abc").map(|e| (e.name, e.data)),
            Some(("uuid".to_owned(), "abc".to_owned()))
        );
        assert_eq!(
            parse_sse_event("event: update\ndata: {\"maxLt\":\"7\"}").map(|e| e.data),
            Some("{\"maxLt\":\"7\"}".to_owned())
        );
    }

    #[test]
    fn joins_multiple_data_lines() {
        assert_eq!(
            parse_sse_event("event: update\ndata: one\ndata: two")
                .map(|e| e.data)
                .unwrap(),
            "one\ntwo"
        );
    }

    #[test]
    fn supports_crlf_and_lf_separators() {
        assert_eq!(
            sse_event_end("event: uuid\r\ndata: abc\r\n\r\nrest"),
            Some((22, 4))
        );
        assert_eq!(
            sse_event_end("event: uuid\ndata: abc\n\nrest"),
            Some((21, 2))
        );
        assert_eq!(sse_event_end("no separator yet"), None);
    }

    #[test]
    fn parses_stream_update_with_fallbacks() {
        assert_eq!(
            parse_stream_update(r#"{"maxLt":"42","genUtime":123}"#),
            AccountUpdate {
                max_lt: 42,
                gen_utime: Some(123),
            }
        );
        assert_eq!(
            parse_stream_update("not-json"),
            AccountUpdate {
                max_lt: 0,
                gen_utime: None,
            }
        );
        assert_eq!(
            parse_stream_update(r#"{"maxLt":"bad"}"#),
            AccountUpdate {
                max_lt: 0,
                gen_utime: None,
            }
        );
    }

    #[test]
    fn parses_numeric_and_string_stream_counters() {
        assert_eq!(
            parse_stream_update(r#"{"maxLt":42,"genUtime":"123"}"#),
            AccountUpdate {
                max_lt: 42,
                gen_utime: Some(123),
            }
        );
        assert_eq!(
            parse_stream_update(r#"{"maxLt":"18446744073709551615","genUtime":4294967296}"#),
            AccountUpdate {
                max_lt: u64::MAX,
                gen_utime: None,
            }
        );
        assert_eq!(parse_stream_counter(r#"{"dropped":9}"#, "dropped"), Some(9));
        assert_eq!(
            parse_stream_counter(r#"{"dropped":"10"}"#, "dropped"),
            Some(10)
        );
        assert_eq!(parse_stream_counter(r#"{"dropped":-1}"#, "dropped"), None);
    }

    #[test]
    fn keep_alive_dropped_count_requests_reconciliation_once() {
        let mut last_dropped = 0;
        let mut last_update = None;

        assert_eq!(
            parse_subscription_notification(
                "keep-alive",
                r#"{"lt":"100","utime":123}"#,
                &mut last_dropped,
                &mut last_update,
            ),
            None
        );
        assert_eq!(
            parse_subscription_notification(
                "keep-alive",
                r#"{"lt":"101","utime":124,"dropped":2}"#,
                &mut last_dropped,
                &mut last_update,
            ),
            Some(AccountUpdate {
                max_lt: 0,
                gen_utime: Some(124),
            })
        );
        assert_eq!(last_dropped, 2);

        assert_eq!(
            parse_subscription_notification(
                "keep-alive",
                r#"{"lt":"102","utime":125,"dropped":2}"#,
                &mut last_dropped,
                &mut last_update,
            ),
            None
        );
    }

    #[test]
    fn update_with_drops_refreshes_and_suppresses_duplicate_keep_alive_hint() {
        let mut last_dropped = 0;
        let mut last_update = None;
        let update = AccountUpdate {
            max_lt: 77,
            gen_utime: Some(200),
        };

        assert_eq!(
            parse_subscription_notification(
                "update",
                r#"{"maxLt":77,"genUtime":200,"dropped":3}"#,
                &mut last_dropped,
                &mut last_update,
            ),
            Some(update)
        );
        assert_eq!(last_dropped, 3);
        assert_eq!(last_update, Some(update));
        assert_eq!(
            parse_subscription_notification(
                "keep-alive",
                r#"{"lt":"300","utime":201,"dropped":3}"#,
                &mut last_dropped,
                &mut last_update,
            ),
            None
        );

        assert_eq!(
            parse_subscription_notification(
                "keep-alive",
                r#"{"lt":"301","utime":202,"dropped":4}"#,
                &mut last_dropped,
                &mut last_update,
            ),
            Some(update)
        );
    }
}
