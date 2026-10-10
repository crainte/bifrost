use base64::Engine;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::events::{CacheStore, QueryEvent};
use crate::{AppState, BlockMode};

pub enum WriterMessage {
    Event(QueryEvent),
    CacheStore(CacheStore),
}
type Error = Box<dyn std::error::Error + Send + Sync>;

/// Owns the ONE bidirectional connection to Erlang: control messages are read
/// from it and events/cache entries are written to it. A single connection means
/// Erlang cannot send control traffic to a socket Rust is not reading. On any
/// failure the connection is dropped and re-established; Erlang re-hydrates on
/// every connect, so nothing missed while disconnected is lost for good.
pub async fn run(
    path: String,
    mut rx: mpsc::Receiver<WriterMessage>,
    ready_tx: mpsc::Sender<()>,
    state: Arc<RwLock<AppState>>,
) {
    loop {
        let stream = match UnixStream::connect(&path).await {
            Ok(s) => s,
            Err(e) => {
                warn!("IPC connect to {} failed: {}, retrying in 1s", path, e);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }
        };
        info!("connected to Erlang IPC at {}", path);
        let (mut reader, mut writer) = stream.into_split();
        let (ack_tx, mut ack_rx) = mpsc::channel(16);
        let outcome = tokio::select! {
            r = read_loop(&mut reader, &ready_tx, &state, &ack_tx) => r,
            w = write_loop(&mut writer, &mut rx, &mut ack_rx) => w,
        };
        match outcome {
            Ok(()) => info!("IPC connection closed, reconnecting"),
            Err(e) => error!(%e, "IPC connection lost, reconnecting"),
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

async fn read_loop(
    reader: &mut tokio::net::unix::OwnedReadHalf,
    ready_tx: &mpsc::Sender<()>,
    state: &Arc<RwLock<AppState>>,
    ack_tx: &mpsc::Sender<serde_json::Value>,
) -> Result<(), Error> {
    loop {
        let mut len_buf = [0u8; 4];
        match reader.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 1_048_576 {
            return Err("IPC frame too large".into());
        }
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).await?;
        // A bad frame is one bad message, not a broken connection: framing is
        // intact (we consumed exactly `len` bytes), so skip it and carry on.
        match serde_json::from_slice::<serde_json::Value>(&buf) {
            Ok(msg) if msg["type"] == "apply_dns_settings" => {
                apply_settings(msg, state, ack_tx).await
            }
            Ok(msg) => handle_control_message(msg, ready_tx, state).await,
            Err(e) => warn!(%e, "skipping malformed IPC frame"),
        }
    }
}

async fn write_loop(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    rx: &mut mpsc::Receiver<WriterMessage>,
    ack_rx: &mut mpsc::Receiver<serde_json::Value>,
) -> Result<(), Error> {
    loop {
        let json = tokio::select! {
            biased;
            Some(ack) = ack_rx.recv() => serde_json::to_vec(&ack)?,
            msg = rx.recv() => match msg {
                Some(WriterMessage::Event(event)) => event.to_json()?,
                Some(WriterMessage::CacheStore(cache)) => cache.to_json()?,
                None => break,
            },
        };
        writer.write_all(&(json.len() as u32).to_be_bytes()).await?;
        writer.write_all(&json).await?;
    }
    // Every sender is gone: the process is shutting down.
    std::future::pending::<()>().await;
    Ok(())
}

async fn apply_settings(
    msg: serde_json::Value,
    state: &Arc<RwLock<AppState>>,
    ack_tx: &mpsc::Sender<serde_json::Value>,
) {
    let revision = msg["revision"].as_u64();
    let fingerprint = msg["fingerprint"].as_str().unwrap_or("").to_string();
    let compiled = if revision.is_none() || fingerprint.is_empty() || fingerprint.len() > 128 {
        Err("missing settings identity".to_string())
    } else {
        serde_json::from_value::<crate::routing::Settings>(msg["settings"].clone())
            .map_err(|e| e.to_string())
            .and_then(crate::routing::Settings::compile)
    };
    let revision = revision.unwrap_or(0);
    let reply = match compiled {
        Ok(c) => {
            let mut s = state.write().await;
            if revision < s.settings_revision
                || (revision == s.settings_revision
                    && !s.settings_fingerprint.is_empty()
                    && fingerprint != s.settings_fingerprint)
            {
                Err("stale settings revision".to_string())
            } else {
                if revision != s.settings_revision || fingerprint != s.settings_fingerprint {
                    s.cache.clear();
                    s.cache
                        .set_limits(c.cache.max_entries, c.cache.min_ttl, c.cache.max_ttl);
                    s.block_mode = c.block_mode;
                    s.routing = Some(Arc::new(c.routing));
                    s.settings_revision = revision;
                    s.settings_fingerprint = fingerprint.clone();
                    s.policy_generation = s.policy_generation.wrapping_add(1);
                }
                Ok(())
            }
        }
        Err(e) => Err(e),
    };
    let message = match reply {
        Ok(()) => {
            serde_json::json!({"type":"dns_settings_applied","revision":revision,"fingerprint":fingerprint})
        }
        Err(e) => serde_json::json!({"type":"dns_settings_rejected","revision":revision,
            "fingerprint":fingerprint,"error":e.chars().take(240).collect::<String>()}),
    };
    if ack_tx.send(message).await.is_err() {
        warn!(revision, "settings acknowledgement channel closed");
    }
}

async fn handle_control_message(
    msg: serde_json::Value,
    ready_tx: &mpsc::Sender<()>,
    state: &Arc<RwLock<AppState>>,
) {
    let msg_type = msg["type"].as_str().unwrap_or("unknown");

    match msg_type {
        "load_blocklist" => {
            let list_id = msg["list_id"].as_str().unwrap_or("unknown").to_string();
            let entries: Vec<String> = msg["entries"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let count = entries.len();
            let mut s = state.write().await;
            s.blocklist.load(&list_id, entries);
            debug!(list_id, count, "loaded blocklist batch");
        }
        "begin_blocklist" => {
            let list_id = msg["list_id"].as_str().unwrap_or("unknown").to_string();
            state.write().await.blocklist.begin(&list_id);
        }
        "commit_blocklist" => {
            let list_id = msg["list_id"].as_str().unwrap_or("unknown").to_string();
            let mut s = state.write().await;
            s.blocklist.commit(&list_id);
            info!(
                list_id,
                count = s.blocklist.len_for_list(&list_id),
                "committed blocklist"
            );
        }
        "set_cache_config" => {
            let max_entries = msg["max_entries"].as_u64().unwrap_or(100_000) as usize;
            let min_ttl = msg["min_ttl"].as_u64().unwrap_or(0) as u32;
            let max_ttl = msg["max_ttl"].as_u64().unwrap_or(u32::MAX as u64) as u32;
            state
                .write()
                .await
                .cache
                .set_limits(max_entries, min_ttl, max_ttl);
            info!(max_entries, min_ttl, max_ttl, "set cache limits");
        }
        "set_acl" => {
            let cidrs: Vec<String> = msg["allowed_clients"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let acl = crate::acl::Acl::from_cidrs(&cidrs);
            info!(entries = acl.len(), "set client ACL");
            state.write().await.acl = acl;
        }
        "clear_blocklist" => {
            let list_id = msg["list_id"].as_str().unwrap_or("unknown").to_string();
            let mut s = state.write().await;
            s.blocklist.clear_list(&list_id);
            info!(list_id, "cleared blocklist");
        }
        "load_rewrites" => {
            let entries: Vec<(String, String)> = msg["entries"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| {
                            let domain = v["domain"].as_str()?.to_string();
                            let target = v["target"].as_str()?.to_string();
                            Some((domain, target))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut s = state.write().await;
            s.rewrites.load(entries);
            info!(count = s.rewrites.len(), "loaded rewrites");
        }
        "load_allowlist" => {
            let entries: Vec<String> = msg["entries"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let mut s = state.write().await;
            s.allowlist.load(entries);
            info!(count = s.allowlist.len(), "loaded allowlist");
        }
        "load_client_blocks" => {
            let entries: Vec<(String, String)> = msg["entries"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| {
                            let client_ip = v["client_ip"].as_str()?.to_string();
                            let domain = v["domain"].as_str()?.to_string();
                            Some((client_ip, domain))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut s = state.write().await;
            s.client_blocks.load(entries);
            info!(count = s.client_blocks.len(), "loaded client blocks");
        }
        "set_upstreams" => {
            let upstreams: Vec<SocketAddr> = msg["upstreams"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| {
                            let addr = v["address"].as_str()?;
                            let port = v["port"].as_u64()?;
                            SocketAddr::from_str(&format!("{}:{}", addr, port)).ok()
                        })
                        .collect()
                })
                .unwrap_or_default();
            let count = upstreams.len();
            let mut s = state.write().await;
            s.forwarder = Arc::new(crate::forwarder::Forwarder::with_upstreams(upstreams));
            info!(count, "set upstreams");
        }
        "set_block_mode" => {
            let mode_str = msg["mode"].as_str().unwrap_or("nxdomain");
            let mode = match mode_str {
                "zero_ip" => BlockMode::ZeroIp,
                "nxdomain" => BlockMode::NXDomain,
                "refused" => BlockMode::Refused,
                "custom_ip" => {
                    let ip_str = msg["custom_ip"].as_str().unwrap_or("0.0.0.0");
                    match IpAddr::from_str(ip_str) {
                        Ok(ip) => BlockMode::CustomIp(ip),
                        Err(_) => {
                            warn!(ip = ip_str, "invalid custom_ip, falling back to NXDomain");
                            BlockMode::NXDomain
                        }
                    }
                }
                _ => {
                    warn!(
                        mode = mode_str,
                        "unknown block mode, falling back to NXDomain"
                    );
                    BlockMode::NXDomain
                }
            };
            let mut s = state.write().await;
            s.block_mode = mode;
            info!(mode = mode_str, "set block mode");
        }
        "set_protection" => {
            let enabled = msg["enabled"].as_bool().unwrap_or(true);
            let mut s = state.write().await;
            s.protection_enabled = enabled;
            info!(enabled, "set protection");
        }
        "reload_complete" => {
            info!("received reload_complete — accepting queries");
            let _ = ready_tx.try_send(());
        }
        "store_cache" => {
            let domain = msg["domain"].as_str().unwrap_or("").to_string();
            let qtype = msg["qtype"].as_u64().unwrap_or(1) as u16;
            let response_b64 = msg["response"].as_str().unwrap_or("");
            let ttl = msg["ttl"].as_u64().unwrap_or(60) as u32;
            let response = match base64::engine::general_purpose::STANDARD.decode(response_b64) {
                Ok(bytes) => bytes,
                Err(e) => {
                    warn!(%e, domain, "failed to decode propagated cache response");
                    return;
                }
            };
            let mut s = state.write().await;
            if s.routing.is_some() {
                let variant = msg["variant"].as_str().unwrap_or("");
                let fingerprint = msg["fingerprint"].as_str().unwrap_or("");
                let expires = msg["expires_at_ms"].as_u64().unwrap_or(0);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(u64::MAX);
                if fingerprint != s.settings_fingerprint
                    || !matches!(variant, "0:0" | "0:1" | "1:0" | "1:1")
                    || expires <= now
                {
                    debug!(
                        domain,
                        qtype, "rejected incompatible propagated cache entry"
                    );
                    return;
                }
                let remaining = (expires - now).div_ceil(1000).min(ttl as u64) as u32;
                let key = format!(
                    "{}|{}:{}:{}",
                    fingerprint,
                    domain.to_lowercase(),
                    qtype,
                    variant
                );
                s.cache.insert_exact(key, response, remaining);
            } else {
                let cache_key = format!("{}:{}", domain.to_lowercase(), qtype);
                s.cache.insert(cache_key, response, ttl);
            }
            debug!(domain, qtype, ttl, "stored propagated cache entry");
        }
        "evict_cache" => {
            let domain = msg["domain"].as_str().unwrap_or("").to_string();
            if domain.is_empty() {
                warn!("evict_cache with empty domain, ignoring");
                return;
            }
            let mut s = state.write().await;
            let n = s.cache.evict_domain(&domain);
            info!(domain, evicted = n, "evicted cache entries");
        }
        "clear_cache" => {
            let mut s = state.write().await;
            s.cache.clear();
            info!("cleared entire DNS cache");
        }
        _ => {
            warn!(%msg_type, "unknown control message type");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Action, QueryEvent};
    use std::time::Duration;
    use tokio::net::UnixListener;

    fn sock_path(tag: &str) -> String {
        let p = std::env::temp_dir().join(format!(
            "bifrost-ipc-{}-{}-{}",
            tag,
            std::process::id(),
            rand::random::<u32>()
        ));
        p.to_string_lossy().into_owned()
    }

    async fn send_frame(s: &mut UnixStream, json: &str) {
        s.write_all(&(json.len() as u32).to_be_bytes())
            .await
            .unwrap();
        s.write_all(json.as_bytes()).await.unwrap();
    }

    async fn read_frame(s: &mut UnixStream) -> serde_json::Value {
        let mut len = [0u8; 4];
        s.read_exact(&mut len).await.unwrap();
        let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
        s.read_exact(&mut buf).await.unwrap();
        serde_json::from_slice(&buf).unwrap()
    }

    fn event(domain: &str) -> WriterMessage {
        WriterMessage::Event(QueryEvent::new(
            "192.168.1.2".into(),
            domain.into(),
            1,
            Action::NoError,
            Action::NoError,
            None,
            None,
            None,
            None,
        ))
    }

    struct Harness {
        listener: UnixListener,
        tx: mpsc::Sender<WriterMessage>,
        ready_rx: mpsc::Receiver<()>,
        state: Arc<RwLock<AppState>>,
    }

    fn start(tag: &str) -> Harness {
        let path = sock_path(tag);
        let listener = UnixListener::bind(&path).unwrap();
        let (tx, rx) = mpsc::channel(64);
        let (ready_tx, ready_rx) = mpsc::channel(4);
        let state = Arc::new(RwLock::new(AppState::new()));
        tokio::spawn(run(path, rx, ready_tx, state.clone()));
        Harness {
            listener,
            tx,
            ready_rx,
            state,
        }
    }

    async fn accept(l: &UnixListener) -> UnixStream {
        tokio::time::timeout(Duration::from_secs(3), l.accept())
            .await
            .expect("Rust never connected")
            .unwrap()
            .0
    }

    async fn no_second_connection(l: &UnixListener) -> bool {
        tokio::time::timeout(Duration::from_millis(1500), l.accept())
            .await
            .is_err()
    }

    #[tokio::test]
    async fn control_and_events_share_one_connection() {
        let mut h = start("one");
        let mut conn = accept(&h.listener).await;
        assert!(
            no_second_connection(&h.listener).await,
            "opened more than one IPC connection"
        );

        send_frame(&mut conn, r#"{"type":"reload_complete"}"#).await;
        tokio::time::timeout(Duration::from_secs(2), h.ready_rx.recv())
            .await
            .expect("control message not received on the connection");

        h.tx.send(event("a.example")).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut conn))
            .await
            .expect("event not sent on the same connection");
        assert_eq!(got["domain"], "a.example");
    }

    #[tokio::test]
    async fn reconnects_after_the_server_drops_it() {
        let h = start("reconnect");
        let first = accept(&h.listener).await;
        drop(first);
        let mut second = accept(&h.listener).await;
        send_frame(
            &mut second,
            r#"{"type":"load_blocklist","list_id":"l","entries":["x.example"]}"#,
        )
        .await;
        h.tx.send(event("after.reconnect")).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(3), read_frame(&mut second))
            .await
            .expect("events not resumed on the new connection");
        assert_eq!(got["domain"], "after.reconnect");
        // Reads and writes are independent; poll for the control message.
        let applied = async {
            while h
                .state
                .read()
                .await
                .blocklist
                .contains("x.example")
                .is_none()
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(2), applied)
            .await
            .expect("control message not applied after reconnect");
    }

    #[tokio::test]
    async fn malformed_frame_is_skipped_without_dropping_the_connection() {
        let h = start("malformed");
        let mut conn = accept(&h.listener).await;
        send_frame(&mut conn, "{not json").await;
        send_frame(
            &mut conn,
            r#"{"type":"load_allowlist","entries":["ok.example"]}"#,
        )
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(h.state.read().await.allowlist.contains("ok.example"));
        assert!(
            no_second_connection(&h.listener).await,
            "reconnected after a bad frame"
        );
    }

    async fn apply(state: &Arc<RwLock<AppState>>, json: &str) {
        let (ready_tx, _r) = mpsc::channel(1);
        handle_control_message(serde_json::from_str(json).unwrap(), &ready_tx, state).await;
    }

    #[tokio::test]
    async fn begin_and_commit_swap_a_list_atomically() {
        let st = Arc::new(RwLock::new(AppState::new()));
        apply(
            &st,
            r#"{"type":"load_blocklist","list_id":"l","entries":["old.example"]}"#,
        )
        .await;
        apply(&st, r#"{"type":"begin_blocklist","list_id":"l"}"#).await;
        apply(
            &st,
            r#"{"type":"load_blocklist","list_id":"l","entries":["new.example"]}"#,
        )
        .await;
        assert_eq!(st.read().await.blocklist.contains("old.example"), Some("l"));
        apply(&st, r#"{"type":"commit_blocklist","list_id":"l"}"#).await;
        assert_eq!(st.read().await.blocklist.contains("old.example"), None);
        assert_eq!(st.read().await.blocklist.contains("new.example"), Some("l"));
    }

    #[tokio::test]
    async fn set_cache_config_applies_ttl_limits() {
        let st = Arc::new(RwLock::new(AppState::new()));
        apply(
            &st,
            r#"{"type":"set_cache_config","max_entries":1000,"min_ttl":60,"max_ttl":3600}"#,
        )
        .await;
        st.write()
            .await
            .cache
            .insert("a:1".into(), vec![1], 999_999);
        let (_, ttl) = st.read().await.cache.lookup("a:1").unwrap();
        assert!(ttl <= 3600);
    }

    fn settings_json(revision: u64, fingerprint: &str, address: &str) -> String {
        serde_json::json!({
            "type": "apply_dns_settings", "revision": revision,
            "fingerprint": fingerprint, "settings": {
                "schema_version": 1,
                "upstreams": {"primary":[{"address":address,"port":53}], "fallback":[],
                              "strategy":"parallel", "timeout_ms":1000, "deadline_ms":3000},
                "routes": [], "cache": {"min_ttl":0,"max_ttl":600,"max_entries":10},
                "blocking": {"mode":"refused","custom_ip":""},
                "reverse_dns": {"enrichment_enabled":false,"route_private_ptr":false,
                                "resolvers":[],"positive_ttl_seconds":21600,"negative_ttl_seconds":300},
                "retention_months": 6
            }
        }).to_string()
    }

    #[tokio::test]
    async fn settings_are_acknowledged_on_a_saturated_connection() {
        let h = start("settings-ack");
        let mut conn = accept(&h.listener).await;
        for i in 0..64 {
            h.tx.send(event(&format!("busy-{i}.example")))
                .await
                .unwrap();
        }
        send_frame(&mut conn, &settings_json(7, "fp-7", "192.0.2.1")).await;
        let ack = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let frame = read_frame(&mut conn).await;
                if frame["type"] == "dns_settings_applied" {
                    return frame;
                }
            }
        })
        .await
        .expect("settings ACK was not sent");
        assert_eq!(ack["revision"], 7);
        assert_eq!(ack["fingerprint"], "fp-7");
        let s = h.state.read().await;
        assert!(s.routing.is_some());
        assert!(matches!(s.block_mode, BlockMode::Refused));
    }

    #[tokio::test]
    async fn stale_or_invalid_settings_do_not_replace_current_settings() {
        let st = Arc::new(RwLock::new(AppState::new()));
        let (ack_tx, mut ack_rx) = mpsc::channel(4);
        apply_settings(
            serde_json::from_str(&settings_json(9, "fp-9", "192.0.2.9")).unwrap(),
            &st,
            &ack_tx,
        )
        .await;
        assert_eq!(ack_rx.recv().await.unwrap()["type"], "dns_settings_applied");
        apply_settings(
            serde_json::from_str(&settings_json(8, "fp-8", "192.0.2.8")).unwrap(),
            &st,
            &ack_tx,
        )
        .await;
        assert_eq!(
            ack_rx.recv().await.unwrap()["type"],
            "dns_settings_rejected"
        );
        apply_settings(
            serde_json::from_str(&settings_json(10, "fp-10", "0.0.0.0")).unwrap(),
            &st,
            &ack_tx,
        )
        .await;
        assert_eq!(
            ack_rx.recv().await.unwrap()["type"],
            "dns_settings_rejected"
        );
        assert_eq!(st.read().await.settings_revision, 9);
    }

    #[tokio::test]
    async fn propagated_cache_requires_matching_policy_and_absolute_expiry() {
        let st = Arc::new(RwLock::new(AppState::new()));
        let (ack_tx, mut ack_rx) = mpsc::channel(4);
        apply_settings(
            serde_json::from_str(&settings_json(1, "current", "192.0.2.1")).unwrap(),
            &st,
            &ack_tx,
        )
        .await;
        ack_rx.recv().await.unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let response = base64::engine::general_purpose::STANDARD.encode([1, 2, 3]);
        for (fingerprint, expiry) in [
            (None, now + 60_000),
            (Some("old"), now + 60_000),
            (Some("current"), now - 1),
        ] {
            let mut msg = serde_json::json!({"type":"store_cache","domain":"peer.example",
                "qtype":1,"response":response,"ttl":60,"variant":"0:0","expires_at_ms":expiry});
            if let Some(fp) = fingerprint {
                msg["fingerprint"] = fp.into();
            }
            apply(&st, &msg.to_string()).await;
            assert_eq!(st.read().await.cache.len(), 0);
            assert!(st
                .read()
                .await
                .cache
                .lookup("current|peer.example:1:0:0")
                .is_none());
        }
        apply(
            &st,
            &serde_json::json!({"type":"store_cache","domain":"peer.example",
            "qtype":1,"response":response,"ttl":600,"variant":"0:0",
            "fingerprint":"current","expires_at_ms":now + 2_000})
            .to_string(),
        )
        .await;
        let (_, ttl) = st
            .read()
            .await
            .cache
            .lookup("current|peer.example:1:0:0")
            .unwrap();
        assert!(ttl <= 2);
    }

    #[tokio::test]
    async fn set_acl_applies_client_networks() {
        let st = Arc::new(RwLock::new(AppState::new()));
        apply(
            &st,
            r#"{"type":"set_acl","allowed_clients":["10.0.0.0/8"]}"#,
        )
        .await;
        assert!(st.read().await.acl.permits("10.1.1.1".parse().unwrap()));
        assert!(!st.read().await.acl.permits("192.168.1.1".parse().unwrap()));
    }
}
