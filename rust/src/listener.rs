use std::net::SocketAddr;
use std::sync::Arc;

use hickory_proto::op::{Edns, Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::events::{Action, CacheStore, QueryEvent, ResponseRecord};
use crate::ipc::WriterMessage;
use crate::rewrites::Target;
use crate::{AppState, BlockMode};

/// Compute the response bytes for a raw query. Returns SERVFAIL bytes if not
/// ready. Shared by both UDP and TCP transports.
async fn process(
    src: SocketAddr,
    data: &[u8],
    state: &Arc<RwLock<AppState>>,
    event_tx: &mpsc::Sender<WriterMessage>,
) -> Vec<u8> {
    let (ready, mode, protection) = {
        let s = state.read().await;
        (s.ready, s.block_mode.clone(), s.protection_enabled)
    };
    if !ready {
        return build_servfail(data);
    }
    match handle_query(src, data, state, event_tx, &mode, protection).await {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(%e, "query handling failed");
            build_servfail(data)
        }
    }
}

pub async fn run_udp(
    state: Arc<RwLock<AppState>>,
    event_tx: mpsc::Sender<WriterMessage>,
    listen_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
    info!("listening on UDP {}", listen_addr);

    let mut buf = vec![0u8; 4096];
    loop {
        // A receive error (e.g. ICMP-induced ECONNREFUSED, ENOBUFS) is about one
        // datagram; it must never take the whole listener down.
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!(%e, "UDP receive failed, continuing");
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                continue;
            }
        };
        let data = buf[..n].to_vec();
        let state = state.clone();
        let event_tx = event_tx.clone();
        let socket = socket.clone();
        // One task per query so a slow upstream never blocks other clients.
        tokio::spawn(async move {
            let resp = process(src, &data, &state, &event_tx).await;
            let resp = truncate_for_client(&data, resp);
            if let Err(e) = socket.send_to(&resp, src).await {
                warn!(%e, "failed to send UDP response");
            }
        });
    }
}

pub struct TcpLimits {
    pub idle: std::time::Duration,
    pub max_conns: usize,
}

pub async fn run_tcp(
    state: Arc<RwLock<AppState>>,
    event_tx: mpsc::Sender<WriterMessage>,
    listen_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!("listening on TCP {}", listen_addr);
    serve_tcp(
        listener,
        state,
        event_tx,
        TcpLimits {
            idle: std::time::Duration::from_secs(10),
            max_conns: 256,
        },
    )
    .await;
    Ok(())
}

pub async fn serve_tcp(
    listener: TcpListener,
    state: Arc<RwLock<AppState>>,
    event_tx: mpsc::Sender<WriterMessage>,
    limits: TcpLimits,
) {
    let slots = Arc::new(tokio::sync::Semaphore::new(limits.max_conns));
    loop {
        // Accept errors (EMFILE under load, aborted handshakes) are transient;
        // returning here would kill DNS-over-TCP for the life of the process.
        let (stream, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                warn!(%e, "TCP accept failed, retrying");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            debug!(%peer, "TCP connection limit reached, closing");
            drop(stream);
            continue;
        };
        let state = state.clone();
        let event_tx = event_tx.clone();
        let idle = limits.idle;
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_tcp_conn(stream, peer, &state, &event_tx, idle).await {
                debug!(%e, "TCP connection closed");
            }
        });
    }
}

/// DNS over TCP: each message is a 2-byte big-endian length prefix followed by
/// the message. A connection may carry multiple queries (RFC 7766 reuse).
async fn handle_tcp_conn(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    state: &Arc<RwLock<AppState>>,
    event_tx: &mpsc::Sender<WriterMessage>,
    idle: std::time::Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        // Every read is bounded: an idle client, or one that announces a length
        // and then stalls, is disconnected instead of holding a slot forever.
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(idle, stream.read_exact(&mut len_buf)).await {
            Err(_) => return Ok(()),
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e.into()),
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 {
            return Ok(());
        }
        let mut msg = vec![0u8; len];
        match tokio::time::timeout(idle, stream.read_exact(&mut msg)).await {
            Err(_) => return Ok(()),
            Ok(r) => {
                r?;
            }
        }

        let resp = process(peer, &msg, state, event_tx).await;
        let resp_len = resp.len();
        if resp_len > u16::MAX as usize {
            warn!(len = resp_len, "TCP response exceeds 65535 bytes, dropping");
            return Ok(());
        }
        stream.write_all(&(resp_len as u16).to_be_bytes()).await?;
        stream.write_all(&resp).await?;
    }
}

async fn handle_query(
    src: SocketAddr,
    data: &[u8],
    state: &Arc<RwLock<AppState>>,
    event_tx: &mpsc::Sender<WriterMessage>,
    mode: &BlockMode,
    protection_enabled: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let request = match Message::from_bytes(data) {
        Ok(msg) => msg,
        Err(e) => {
            warn!(%e, "failed to parse DNS query");
            return Ok(build_servfail(data));
        }
    };

    let rejection =
        if request.metadata.message_type != MessageType::Query || request.queries.len() != 1 {
            Some(ResponseCode::FormErr)
        } else if request.metadata.op_code != hickory_proto::op::OpCode::Query {
            Some(ResponseCode::NotImp)
        } else if request.queries[0].query_class() != hickory_proto::rr::DNSClass::IN {
            Some(ResponseCode::Refused)
        } else {
            None
        };
    if let Some(rcode) = rejection {
        let mut response = Message::new(
            request.metadata.id,
            MessageType::Response,
            request.metadata.op_code,
        );
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.metadata.response_code = rcode;
        response.add_queries(request.queries.to_vec());
        return Ok(response.to_bytes()?);
    }

    let question = match request.queries.first() {
        Some(q) => q,
        None => {
            warn!("query has no question section");
            return Ok(build_servfail(data));
        }
    };

    if !state.read().await.acl.permits(src.ip()) {
        let mut response = Message::new(
            request.metadata.id,
            MessageType::Response,
            request.metadata.op_code,
        );
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.add_queries(request.queries.to_vec());
        response.metadata.response_code = ResponseCode::Refused;
        if let Err(e) = event_tx.try_send(WriterMessage::Event(QueryEvent::new(
            src.ip().to_string(),
            question
                .name()
                .to_ascii()
                .to_ascii_lowercase()
                .trim_end_matches('.')
                .to_string(),
            question.query_type().into(),
            Action::Refused,
            Action::Refused,
            None,
            None,
            None,
            None,
        ))) {
            warn!(%e, "failed to send query event");
        }
        return Ok(response.to_bytes()?);
    }

    // Wire form, lowercased: lists store ASCII (xn--) names, and to_utf8() would
    // decode punycode and backslash-escape special bytes, so nothing would match.
    let domain = question.name().to_ascii().to_ascii_lowercase();
    let domain_trimmed = domain.trim_end_matches('.');
    let qtype: u16 = question.query_type().into();
    let (routing, legacy_forwarder, fingerprint) = {
        let s = state.read().await;
        (
            s.routing.clone(),
            s.forwarder.clone(),
            s.settings_fingerprint.clone(),
        )
    };
    let variant = cache_variant(&request);
    let cache_key = if routing.is_some() {
        variant
            .as_ref()
            .map(|v| format!("{}|{}:{}:{}", fingerprint, domain_trimmed, qtype, v))
    } else {
        Some(format!("{}:{}", domain_trimmed, qtype))
    };

    {
        let s = state.read().await;
        if let Some(target) = s.rewrites.lookup(domain_trimmed) {
            let response = build_rewrite_response(&request, target);
            let client_rcode = response.metadata.response_code;
            let bytes = response.to_bytes()?;
            drop(s);

            if let Err(e) = event_tx.try_send(WriterMessage::Event(QueryEvent::new(
                src.ip().to_string(),
                domain_trimmed.to_string(),
                qtype,
                Action::BifrostRW,
                action_from_rcode(client_rcode),
                None,
                None,
                None,
                None,
            ))) {
                warn!(%e, "failed to send query event");
            }
            debug!(client=%src.ip(), domain=%domain_trimmed, qtype, "rewritten");
            return Ok(bytes);
        }
    }

    // CNAME cloaking check on the answer (see blocked_cname): only while
    // filtering, and never for an allowlisted query name, which is how an
    // operator unblocks a cloaked name from the query log.
    let mut check_cnames = protection_enabled;
    if protection_enabled {
        let s = state.read().await;
        // Allowlist takes precedence over blocklist: a match bypasses blocking
        // (emit BIFROST_ALLOW, fall through to cache/forward for a real answer).
        let allowed = s.allowlist.contains(domain_trimmed);
        if allowed {
            check_cnames = false;
            drop(s);
            if let Err(e) = event_tx.try_send(WriterMessage::Event(QueryEvent::new(
                src.ip().to_string(),
                domain_trimmed.to_string(),
                qtype,
                Action::BifrostAllow,
                Action::BifrostAllow,
                None,
                None,
                None,
                None,
            ))) {
                warn!(%e, "failed to send query event");
            }
            debug!(client=%src.ip(), domain=%domain_trimmed, qtype, "allowlisted, bypassing block");
        } else {
            // Per-client block takes precedence, then global blocklist. Both
            // produce a BIFROST_BLOCK; list_id distinguishes the source.
            let block_reason: Option<String> = if s.client_blocks.contains(src.ip(), domain_trimmed)
            {
                Some(format!("client:{}", src.ip()))
            } else {
                s.blocklist
                    .contains(domain_trimmed)
                    .map(|id| id.to_string())
            };
            if let Some(list_id) = block_reason {
                let response = build_blocked_response(&request, mode)?;
                let client_rcode = response.metadata.response_code;
                let bytes = response.to_bytes()?;
                drop(s);

                if let Err(e) = event_tx.try_send(WriterMessage::Event(QueryEvent::new(
                    src.ip().to_string(),
                    domain_trimmed.to_string(),
                    qtype,
                    Action::BifrostBlock,
                    action_from_rcode(client_rcode),
                    Some(15),
                    Some(list_id.clone()),
                    None,
                    None,
                ))) {
                    warn!(%e, "failed to send query event");
                }
                debug!(client=%src.ip(), domain=%domain_trimmed, qtype, %list_id, "blocked");
                return Ok(bytes);
            }
        }
    }

    {
        let s = state.read().await;
        if let Some((cached, remaining_ttl)) =
            cache_key.as_ref().and_then(|key| s.cache.lookup(key))
        {
            let cached_msg = Message::from_bytes(&cached).ok();
            // Checked on hits too: an answer cached before its target was
            // listed, or propagated from a peer, must not bypass the block.
            if check_cnames {
                if let Some(msg) = cached_msg.as_ref() {
                    if let Some((target, list_id)) = blocked_cname(msg, &s.blocklist, &s.allowlist)
                    {
                        drop(s);
                        return cname_block(
                            &request,
                            mode,
                            msg,
                            src,
                            domain_trimmed,
                            qtype,
                            &target,
                            list_id,
                            event_tx,
                        );
                    }
                }
            }
            let mut response = cached.clone();
            let cached_rcode = cached_msg
                .as_ref()
                .map(|m| action_from_rcode(m.metadata.response_code))
                .unwrap_or(Action::Unknown);
            let id_bytes = request.metadata.id.to_be_bytes();
            response[..2].copy_from_slice(&id_bytes);

            // Rewrite TTL in each answer to reflect remaining time, and echo the
            // asker's own question: the cached bytes carry the FIRST asker's
            // letter case, which 0x20-randomising resolvers would reject.
            if let Ok(mut msg) = Message::from_bytes(&response) {
                for ans in &mut msg.answers {
                    ans.ttl = remaining_ttl;
                }
                for ans in &mut msg.authorities {
                    ans.ttl = ans.ttl.min(remaining_ttl);
                }
                for ans in &mut msg.additionals {
                    ans.ttl = ans.ttl.min(remaining_ttl);
                }
                msg.queries.clear();
                msg.add_queries(request.queries.to_vec());
                if let Ok(updated) = msg.to_bytes() {
                    response = updated;
                }
            }

            if let Err(e) = event_tx.try_send(WriterMessage::Event(QueryEvent::new(
                src.ip().to_string(),
                domain_trimmed.to_string(),
                qtype,
                Action::BifrostCache,
                cached_rcode,
                None,
                None,
                None,
                None,
            ))) {
                warn!(%e, "failed to send query event");
            }
            debug!(client=%src.ip(), domain=%domain_trimmed, qtype, "cache hit");
            return Ok(response);
        }
    }

    // Clone the forwarder out and DROP the guard before awaiting the network:
    // tokio's RwLock is fair, so a guard held across a slow upstream lets one
    // queued writer stall every other query behind it.
    let forwarder = match &routing {
        Some(policy) => match policy.decide(domain_trimmed, qtype) {
            crate::routing::Decision::Forward(f) => f,
            crate::routing::Decision::PrivateNegative => {
                let mut response = Message::new(
                    request.metadata.id,
                    MessageType::Response,
                    request.metadata.op_code,
                );
                response.metadata.recursion_desired = request.metadata.recursion_desired;
                response.metadata.recursion_available = true;
                response.metadata.response_code = ResponseCode::NXDomain;
                response.add_queries(request.queries.to_vec());
                return Ok(response.to_bytes()?);
            }
        },
        None => legacy_forwarder,
    };
    let (upstream_response, latency_us) = {
        match forwarder.forward(data).await {
            Ok(r) => r,
            Err(e) => {
                warn!(%e, "upstream forward failed, sending SERVFAIL");
                if let Err(e) = event_tx.try_send(WriterMessage::Event(QueryEvent::new(
                    src.ip().to_string(),
                    domain_trimmed.to_string(),
                    qtype,
                    Action::ServFail,
                    Action::ServFail,
                    None,
                    None,
                    None,
                    None,
                ))) {
                    warn!(%e, "failed to send query event");
                }
                debug!(client=%src.ip(), domain=%domain_trimmed, qtype, "upstream failed");
                return Ok(build_servfail(data));
            }
        }
    };

    let upstream_msg = Message::from_bytes(&upstream_response).ok();
    // Before caching: a cloaked answer is never cached or propagated.
    if check_cnames {
        if let Some(msg) = upstream_msg.as_ref() {
            let hit = {
                let s = state.read().await;
                blocked_cname(msg, &s.blocklist, &s.allowlist)
            };
            if let Some((target, list_id)) = hit {
                return cname_block(
                    &request,
                    mode,
                    msg,
                    src,
                    domain_trimmed,
                    qtype,
                    &target,
                    list_id,
                    event_tx,
                );
            }
        }
    }
    if let (Some(ttl), Some(cache_key)) = (upstream_msg.as_ref().and_then(cache_ttl), cache_key) {
        let inserted = {
            let mut s = state.write().await;
            if routing.is_none() || s.settings_fingerprint == fingerprint {
                s.cache.insert(cache_key, upstream_response.clone(), ttl);
                true
            } else {
                false
            }
        };
        if inserted {
            let store = CacheStore::new(
                domain_trimmed.to_string(),
                qtype,
                upstream_response.clone(),
                ttl,
            );
            let store = match (&routing, variant) {
                (Some(_), Some(v)) => store.tagged(fingerprint.clone(), v),
                _ => store,
            };
            if let Err(e) = event_tx.try_send(WriterMessage::CacheStore(store)) {
                warn!(%e, "failed to send cache store message");
            }
        }
    }

    let action = upstream_msg
        .as_ref()
        .map(|m| action_from_rcode(m.metadata.response_code))
        .unwrap_or(Action::Unknown);
    let client_rcode = action.clone();

    if let Err(e) = event_tx.try_send(WriterMessage::Event(QueryEvent::new(
        src.ip().to_string(),
        domain_trimmed.to_string(),
        qtype,
        action,
        client_rcode,
        None,
        None,
        Some(latency_us as i32),
        upstream_msg.as_ref().map(extract_response_records),
    ))) {
        warn!(%e, "failed to send query event");
    }
    debug!(client=%src.ip(), domain=%domain_trimmed, qtype, latency=%latency_us, "forwarded");

    Ok(upstream_response)
}

/// CNAME cloaking: a tracker served behind a first-party name
/// (metrics.shop.com CNAME c1.tracker.net). Returns `(target, list_id)` for the
/// first CNAME target in the answer that the blocklist (including manual
/// blocks, which load as the `manual` list) covers, with the same semantics as
/// the query check: most specific entry, same-list `@@` exceptions honoured,
/// and an allowlisted target is never blocked. Per-client blocks are not
/// applied to targets, so a cached answer means the same for every client.
fn blocked_cname(
    msg: &Message,
    blocklist: &crate::blocklist::Blocklist,
    allowlist: &crate::allowlist::Allowlist,
) -> Option<(String, String)> {
    msg.answers.iter().find_map(|r| match &r.data {
        RData::CNAME(c) => {
            let target = c.0.to_ascii().to_ascii_lowercase();
            let target = target.trim_end_matches('.');
            if allowlist.contains(target) {
                return None;
            }
            blocklist
                .contains(target)
                .map(|id| (target.to_string(), id.to_string()))
        }
        _ => None,
    })
}

/// The configured block response for a cloaked answer. Logged as an ordinary
/// BIFROST_BLOCK attributed to the list that matched the TARGET, with the
/// answer's records attached so the query log can show the CNAME.
#[allow(clippy::too_many_arguments)]
fn cname_block(
    request: &Message,
    mode: &BlockMode,
    answer: &Message,
    src: SocketAddr,
    domain: &str,
    qtype: u16,
    target: &str,
    list_id: String,
    event_tx: &mpsc::Sender<WriterMessage>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let response = build_blocked_response(request, mode)?;
    let client_rcode = response.metadata.response_code;
    let bytes = response.to_bytes()?;
    if let Err(e) = event_tx.try_send(WriterMessage::Event(QueryEvent::new(
        src.ip().to_string(),
        domain.to_string(),
        qtype,
        Action::BifrostBlock,
        action_from_rcode(client_rcode),
        Some(15),
        Some(list_id.clone()),
        None,
        Some(extract_response_records(answer)),
    ))) {
        warn!(%e, "failed to send query event");
    }
    debug!(client=%src.ip(), %domain, qtype, %target, %list_id, "blocked via CNAME");
    Ok(bytes)
}

fn build_blocked_response(
    request: &Message,
    mode: &BlockMode,
) -> Result<Message, Box<dyn std::error::Error + Send + Sync>> {
    let mut response = Message::new(
        request.metadata.id,
        MessageType::Response,
        request.metadata.op_code,
    );
    response.metadata.recursion_desired = true;
    response.metadata.recursion_available = true;
    response.add_queries(request.queries.to_vec());

    match mode {
        BlockMode::NXDomain => {
            response.metadata.response_code = ResponseCode::NXDomain;
        }
        BlockMode::Refused => {
            response.metadata.response_code = ResponseCode::Refused;
        }
        BlockMode::ZeroIp => {
            response.metadata.response_code = ResponseCode::NoError;
            let question = request.queries.first();
            if let Some(q) = question {
                let qtype = q.query_type();
                let name = q.name().clone();
                if qtype == RecordType::A {
                    let mut record = Record::from_rdata(
                        name,
                        60,
                        RData::A(hickory_proto::rr::rdata::A::new(0, 0, 0, 0)),
                    );
                    record.dns_class = q.query_class();
                    response.add_answer(record);
                } else if qtype == RecordType::AAAA {
                    let mut record = Record::from_rdata(
                        name,
                        60,
                        RData::AAAA(hickory_proto::rr::rdata::AAAA::new(0, 0, 0, 0, 0, 0, 0, 0)),
                    );
                    record.dns_class = q.query_class();
                    response.add_answer(record);
                }
            }
        }
        BlockMode::CustomIp(ip) => {
            response.metadata.response_code = ResponseCode::NoError;
            let question = request.queries.first();
            if let Some(q) = question {
                let qtype = q.query_type();
                let name = q.name().clone();
                if qtype == RecordType::A {
                    if let std::net::IpAddr::V4(v4) = ip {
                        let mut record = Record::from_rdata(
                            name,
                            60,
                            RData::A(hickory_proto::rr::rdata::A(*v4)),
                        );
                        record.dns_class = q.query_class();
                        response.add_answer(record);
                    }
                } else if qtype == RecordType::AAAA {
                    if let std::net::IpAddr::V6(v6) = ip {
                        let mut record = Record::from_rdata(
                            name,
                            60,
                            RData::AAAA(hickory_proto::rr::rdata::AAAA(*v6)),
                        );
                        record.dns_class = q.query_class();
                        response.add_answer(record);
                    }
                }
            }
        }
    }

    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    edns.options_mut()
        .insert(EdnsOption::Unknown(15, vec![0, 15]));
    response.edns = Some(edns);

    Ok(response)
}

fn build_rewrite_response(request: &Message, target: &Target) -> Message {
    let mut response = Message::new(
        request.metadata.id,
        MessageType::Response,
        request.metadata.op_code,
    );
    response.metadata.recursion_desired = true;
    response.metadata.recursion_available = true;
    response.add_queries(request.queries.to_vec());
    response.metadata.response_code = ResponseCode::NoError;

    if let Some(q) = request.queries.first() {
        let qtype = q.query_type();
        let name = q.name().clone();
        let dns_class = q.query_class();

        match target {
            // A record only answers A queries; AAAA only AAAA. A mismatched
            // qtype yields an empty NOERROR (correct: the name exists, no such type).
            Target::Ip(std::net::IpAddr::V4(v4)) if qtype == RecordType::A => {
                let mut record =
                    Record::from_rdata(name, 60, RData::A(hickory_proto::rr::rdata::A(*v4)));
                record.dns_class = dns_class;
                response.add_answer(record);
            }
            Target::Ip(std::net::IpAddr::V6(v6)) if qtype == RecordType::AAAA => {
                let mut record =
                    Record::from_rdata(name, 60, RData::AAAA(hickory_proto::rr::rdata::AAAA(*v6)));
                record.dns_class = dns_class;
                response.add_answer(record);
            }
            // CNAME answers any qtype — resolver follows the alias for the real type.
            Target::Cname(name) => {
                if let Ok(mut cname) = Name::from_utf8(name) {
                    cname.set_fqdn(true);
                    let mut record = Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::CNAME(hickory_proto::rr::rdata::CNAME(cname)),
                    );
                    record.dns_class = dns_class;
                    response.add_answer(record);
                }
            }
            _ => {}
        }
    }

    response
}

/// How long an upstream answer may be cached, or None if it must not be.
/// Positive answers live for their shortest record TTL. NXDOMAIN and NODATA
/// live for the RFC 2308 negative TTL, min(SOA TTL, SOA MINIMUM), and are not
/// cached at all without an SOA. Failures (SERVFAIL, REFUSED, ...) and
/// truncated answers are never cached: caching a transient failure would
/// replay it to every client, and to every peer, for the whole TTL.
fn cache_variant(request: &Message) -> Option<String> {
    let (do_bit, ecs) = request
        .edns
        .as_ref()
        .map(|e| {
            (
                e.flags().dnssec_ok,
                e.options()
                    .as_ref()
                    .iter()
                    .any(|(code, _)| u16::from(*code) == 8),
            )
        })
        .unwrap_or((false, false));
    (!ecs).then(|| {
        format!(
            "{}:{}",
            do_bit as u8, request.metadata.checking_disabled as u8
        )
    })
}

fn cache_ttl(msg: &Message) -> Option<u32> {
    if msg.metadata.truncation {
        return None;
    }
    let negative = || {
        msg.authorities.iter().find_map(|r| match &r.data {
            RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
            _ => None,
        })
    };
    match msg.metadata.response_code {
        ResponseCode::NoError if !msg.answers.is_empty() => msg.answers.iter().map(|r| r.ttl).min(),
        ResponseCode::NoError | ResponseCode::NXDomain => negative(),
        _ => None,
    }
}

fn action_from_rcode(rcode: ResponseCode) -> Action {
    match rcode {
        ResponseCode::NoError => Action::NoError,
        ResponseCode::FormErr => Action::FormErr,
        ResponseCode::ServFail => Action::ServFail,
        ResponseCode::NXDomain => Action::NXDomain,
        ResponseCode::NotImp => Action::NotImp,
        ResponseCode::Refused => Action::Refused,
        ResponseCode::YXDomain => Action::YXDomain,
        ResponseCode::YXRRSet => Action::YXRRSet,
        ResponseCode::NXRRSet => Action::NXRRSet,
        ResponseCode::NotAuth => Action::NotAuth,
        ResponseCode::NotZone => Action::NotZone,
        _ => Action::Unknown,
    }
}

fn extract_response_records(msg: &Message) -> Vec<ResponseRecord> {
    msg.answers
        .iter()
        .map(|r| {
            let rtype = r.record_type().to_string();
            let value = match &r.data {
                RData::A(addr) => addr.0.to_string(),
                RData::AAAA(addr) => addr.0.to_string(),
                RData::CNAME(name) => name.to_string(),
                RData::MX(mx) => format!("{} {}", mx.preference, mx.exchange),
                RData::TXT(txt) => txt.to_string(),
                RData::NS(ns) => ns.to_string(),
                RData::PTR(ptr) => ptr.to_string(),
                RData::SOA(soa) => format!("{} {}", soa.mname, soa.rname),
                RData::SRV(srv) => format!(
                    "{} {} {} {}",
                    srv.priority, srv.weight, srv.port, srv.target
                ),
                data => format!("{:?}", data),
            };
            ResponseRecord { rtype, value }
        })
        .collect()
}

/// Build SERVFAIL response bytes for a query, preserving its ID + question.
/// Falls back to a bare SERVFAIL if the query won't parse.
fn build_servfail(query: &[u8]) -> Vec<u8> {
    let mut response = Message::new(0, MessageType::Response, hickory_proto::op::OpCode::Query);
    response.metadata.response_code = ResponseCode::ServFail;
    response.metadata.recursion_desired = true;
    if let Ok(request) = Message::from_bytes(query) {
        response.metadata.id = request.metadata.id;
        response.add_queries(request.queries.to_vec());
    }
    response.to_bytes().unwrap_or_else(|_| {
        // Absolute fallback: 12-byte header echoing ID with SERVFAIL rcode.
        let mut hdr = vec![0u8; 12];
        if query.len() >= 2 {
            hdr[0] = query[0];
            hdr[1] = query[1];
        }
        hdr[2] = 0x80; // QR=1
        hdr[3] = 0x02; // RCODE=SERVFAIL
        hdr
    })
}

/// Client-facing EDNS payload enforcement (UDP only). If `response` exceeds the
/// UDP payload size the client advertised in its query's EDNS OPT (default 512
/// when the client sent no EDNS), return a truncated response — same header with
/// the TC bit set and all records stripped — so the client retries over TCP.
/// Responses within the limit are returned unchanged.
fn truncate_for_client(query: &[u8], response: Vec<u8>) -> Vec<u8> {
    let max = client_max_payload(query);
    if response.len() <= max {
        return response;
    }
    // Rebuild a minimal truncated response preserving id + question.
    let mut trunc = Message::new(0, MessageType::Response, hickory_proto::op::OpCode::Query);
    trunc.metadata.truncation = true;
    trunc.metadata.recursion_desired = true;
    trunc.metadata.recursion_available = true;
    if let Ok(req) = Message::from_bytes(query) {
        trunc.metadata.id = req.metadata.id;
        trunc.metadata.response_code = ResponseCode::NoError;
        trunc.add_queries(req.queries.to_vec());
    }
    match trunc.to_bytes() {
        // Only substitute if it actually fits; otherwise send original bytes and
        // let the client cope rather than risk an unparsable reply.
        Ok(bytes) if bytes.len() <= max => bytes,
        _ => response,
    }
}

/// The UDP payload size a client advertised via EDNS, or 512 if it sent none.
fn client_max_payload(query: &[u8]) -> usize {
    match Message::from_bytes(query) {
        Ok(msg) => msg
            .edns
            .as_ref()
            .map(|e| e.max_payload() as usize)
            .filter(|&s| s >= 512)
            .unwrap_or(512),
        Err(_) => 512,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;

    fn query(name: &str, qtype: RecordType) -> Message {
        let mut m = Message::new(0, MessageType::Query, hickory_proto::op::OpCode::Query);
        m.metadata.id = 0x1234;
        // from_ascii, not from_utf8: from_utf8 applies IDNA mapping, which
        // lowercases, so mixed-case tests would silently send lowercase.
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
        m
    }

    #[test]
    fn rewrite_a_query_to_ip_answers_a_record() {
        let req = query("nas.home.", RecordType::A);
        let resp = build_rewrite_response(&req, &Target::Ip("192.168.1.5".parse().unwrap()));
        assert_eq!(resp.metadata.id, 0x1234);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].data {
            RData::A(a) => assert_eq!(a.0.to_string(), "192.168.1.5"),
            other => panic!("expected A, got {:?}", other),
        }
    }

    #[test]
    fn rewrite_aaaa_query_to_v4_ip_yields_empty_noerror() {
        // AAAA query but rewrite target is IPv4 → name exists, no AAAA. Empty NOERROR.
        let req = query("nas.home.", RecordType::AAAA);
        let resp = build_rewrite_response(&req, &Target::Ip("192.168.1.5".parse().unwrap()));
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 0);
    }

    #[test]
    fn rewrite_cname_answers_any_qtype() {
        let req = query("www.home.", RecordType::A);
        let resp = build_rewrite_response(&req, &Target::Cname("server.home".into()));
        assert_eq!(resp.answers.len(), 1);
        match &resp.answers[0].data {
            RData::CNAME(c) => assert_eq!(c.0.to_utf8(), "server.home."),
            other => panic!("expected CNAME, got {:?}", other),
        }
    }

    // ── build_servfail ──
    #[test]
    fn servfail_preserves_id_and_question() {
        let q = query("example.com.", RecordType::A);
        let bytes = build_servfail(&q.to_bytes().unwrap());
        let resp = Message::from_bytes(&bytes).unwrap();
        assert_eq!(resp.metadata.id, 0x1234);
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(resp.queries.len(), 1);
    }

    #[test]
    fn servfail_on_garbage_query_still_returns_bytes() {
        let bytes = build_servfail(&[0xDE, 0xAD, 0xBE, 0xEF]);
        // Must be a non-empty response even for unparseable input.
        assert!(bytes.len() >= 12);
    }

    // ── handle_query end-to-end (returns response bytes, no socket) ──
    fn test_state() -> Arc<RwLock<AppState>> {
        Arc::new(RwLock::new(AppState::new()))
    }

    async fn run_handler(st: &Arc<RwLock<AppState>>, q: &Message) -> Message {
        let (tx, _rx) = mpsc::channel(16);
        let src: SocketAddr = "192.168.1.42:5000".parse().unwrap();
        let bytes = handle_query(
            src,
            &q.to_bytes().unwrap(),
            st,
            &tx,
            &BlockMode::ZeroIp,
            true,
        )
        .await
        .unwrap();
        Message::from_bytes(&bytes).unwrap()
    }

    #[tokio::test]
    async fn non_in_queries_are_refused_before_local_policy_even_when_paused() {
        use hickory_proto::rr::DNSClass;
        let st = test_state();
        st.write()
            .await
            .rewrites
            .load(vec![("version.bind".into(), "192.0.2.1".into())]);
        for class in [DNSClass::CH, DNSClass::HS] {
            for name in ["version.bind.", "id.server.", "hostname.bind."] {
                for enabled in [true, false] {
                    let mut req = query(name, RecordType::TXT);
                    req.queries[0].set_query_class(class);
                    let (tx, _rx) = mpsc::channel(16);
                    let bytes = handle_query(
                        "192.168.1.42:5000".parse().unwrap(),
                        &req.to_bytes().unwrap(),
                        &st,
                        &tx,
                        &BlockMode::ZeroIp,
                        enabled,
                    )
                    .await
                    .unwrap();
                    let resp = Message::from_bytes(&bytes).unwrap();
                    assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
                    assert_eq!(resp.metadata.id, req.metadata.id);
                    assert_eq!(resp.queries, req.queries);
                    assert!(resp.answers.is_empty());
                }
            }
        }
    }

    #[tokio::test]
    async fn conditional_routes_never_fall_back_to_default_group() {
        use crate::routing::{Group, Route, Routing};
        let healthy_default = scripted_upstream(|req| {
            let mut r = Message::new(0, MessageType::Query, hickory_proto::op::OpCode::Query);
            r.add_answer(Record::from_rdata(
                req.queries[0].name().clone(),
                300,
                RData::A(hickory_proto::rr::rdata::A::new(1, 2, 3, 4)),
            ));
            r
        })
        .await;
        let st = test_state();
        let default: Group = serde_json::from_value(serde_json::json!({
            "primary": [{"address":"127.0.0.1", "port":healthy_default.port()}], "fallback": [],
            "strategy":"sequential", "timeout_ms":100, "deadline_ms":100
        }))
        .unwrap();
        let route: Route = serde_json::from_value(serde_json::json!({
            "id":"lan", "domains":["internal"],
            "primary": [{"address":"127.0.0.1", "port":9}], "fallback": [],
            "strategy":"sequential", "timeout_ms":100, "deadline_ms":100
        }))
        .unwrap();
        st.write().await.routing = Some(Arc::new(Routing::compile(&default, vec![route]).unwrap()));
        let resp = run_handler(&st, &query("host.internal.", RecordType::A)).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn policy_cache_is_isolated_and_propagation_is_tagged() {
        let st = state_with_upstream(|req| {
            let mut r = Message::new(0, MessageType::Query, hickory_proto::op::OpCode::Query);
            let name = req.queries[0].name().clone();
            r.add_answer(Record::from_rdata(
                name,
                300,
                RData::A(hickory_proto::rr::rdata::A::new(1, 2, 3, 4)),
            ));
            r
        })
        .await;
        {
            let mut s = st.write().await;
            let up = s.forwarder.clone();
            s.routing = Some(Arc::new(crate::routing::Routing::from_forwarder(up)));
            s.settings_fingerprint = "policy-a".into();
        }
        let (_, sent) = run_collecting(&st, &query("tagged.example.", RecordType::A)).await;
        let store = sent
            .iter()
            .find_map(|m| match m {
                WriterMessage::CacheStore(s) => Some(s),
                _ => None,
            })
            .expect("cache store was not propagated");
        assert_eq!(store.fingerprint.as_deref(), Some("policy-a"));
        assert!(store.expires_at_ms.unwrap() > store.ttl as u64);
        let (_, sent) = run_collecting(&st, &query("tagged.example.", RecordType::A)).await;
        assert!(sent.iter().any(
            |m| matches!(m, WriterMessage::Event(e) if matches!(e.action, Action::BifrostCache))
        ));
        st.write().await.settings_fingerprint = "policy-b".into();
        let (_, sent) = run_collecting(&st, &query("tagged.example.", RecordType::A)).await;
        assert!(!sent.iter().any(
            |m| matches!(m, WriterMessage::Event(e) if matches!(e.action, Action::BifrostCache))
        ));
    }

    #[tokio::test]
    async fn stale_inflight_response_cannot_populate_new_policy_cache() {
        let up = slow_upstream(std::time::Duration::from_millis(200)).await;
        let st = test_state();
        {
            let mut s = st.write().await;
            let f = Arc::new(crate::forwarder::Forwarder::with_upstreams(vec![up]));
            s.forwarder = f.clone();
            s.routing = Some(Arc::new(crate::routing::Routing::from_forwarder(f)));
            s.settings_fingerprint = "old".into();
            s.ready = true;
        }
        let st2 = st.clone();
        let task = tokio::spawn(async move {
            run_collecting(&st2, &query("inflight.example.", RecordType::A)).await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        st.write().await.settings_fingerprint = "new".into();
        let (_, sent) = task.await.unwrap();
        assert_eq!(cache_stores(&sent), 0);
        assert!(st
            .read()
            .await
            .cache
            .lookup("new|inflight.example:1:0:0")
            .is_none());
    }

    #[tokio::test]
    async fn ecs_queries_bypass_shared_cache() {
        let st = state_with_upstream(|req| {
            let mut r = Message::new(0, MessageType::Query, hickory_proto::op::OpCode::Query);
            r.add_answer(Record::from_rdata(
                req.queries[0].name().clone(),
                300,
                RData::A(hickory_proto::rr::rdata::A::new(1, 2, 3, 4)),
            ));
            r
        })
        .await;
        {
            let mut s = st.write().await;
            let f = s.forwarder.clone();
            s.routing = Some(Arc::new(crate::routing::Routing::from_forwarder(f)));
            s.settings_fingerprint = "ecs".into();
        }
        let mut q = query("ecs.example.", RecordType::A);
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Unknown(8, vec![0, 1, 24, 0, 192, 0, 2]));
        q.edns = Some(edns);
        let (_, sent) = run_collecting(&st, &q).await;
        assert_eq!(cache_stores(&sent), 0);
    }

    #[tokio::test]
    async fn private_reverse_without_route_never_reaches_default_upstream() {
        let st = state_with_upstream(|_| panic!("private PTR leaked")).await;
        {
            let mut s = st.write().await;
            let f = s.forwarder.clone();
            s.routing = Some(Arc::new(crate::routing::Routing::from_forwarder(f)));
        }
        let resp = run_handler(&st, &query("1.0.0.10.in-addr.arpa.", RecordType::PTR)).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn multiple_questions_are_rejected_before_rewrites() {
        let st = test_state();
        st.write()
            .await
            .rewrites
            .load(vec![("local.example".into(), "192.0.2.1".into())]);
        let mut req = query("local.example.", RecordType::A);
        req.add_query(req.queries[0].clone());
        let resp = run_handler(&st, &req).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::FormErr);
        assert!(resp.answers.is_empty());
    }

    #[tokio::test]
    async fn unsupported_opcode_is_not_forwarded() {
        let st = test_state();
        let mut req = query("example.org.", RecordType::A);
        req.metadata.op_code = hickory_proto::op::OpCode::Update;
        let resp = run_handler(&st, &req).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NotImp);
        assert!(resp.answers.is_empty());
    }

    #[tokio::test]
    async fn handler_blocks_listed_domain_with_zero_ip() {
        let st = test_state();
        {
            st.write()
                .await
                .blocklist
                .load("test", vec!["ads.example.com".into()]);
        }
        let resp = run_handler(&st, &query("ads.example.com.", RecordType::A)).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        match resp.answers.first().map(|r| &r.data) {
            Some(RData::A(a)) => assert_eq!(a.0.to_string(), "0.0.0.0"),
            other => panic!("expected 0.0.0.0 block answer, got {:?}", other),
        }
        // EDE 15 attached.
        assert!(resp.edns.as_ref().is_some());
    }

    fn is_zero_ip_block(resp: &Message) -> bool {
        matches!(resp.answers.first().map(|r| &r.data),
                 Some(RData::A(a)) if a.0.is_unspecified())
    }

    async fn first_event(rx: &mut mpsc::Receiver<WriterMessage>) -> QueryEvent {
        loop {
            match rx.recv().await.expect("event channel closed") {
                WriterMessage::Event(e) => return e,
                _ => continue,
            }
        }
    }

    #[tokio::test]
    async fn handler_blocks_mixed_case_query() {
        // Resolvers using 0x20 case randomisation send names like this; they
        // must be blocked exactly like the lowercase form.
        let st = test_state();
        {
            st.write()
                .await
                .blocklist
                .load("test", vec!["ads.example.com".into()]);
        }
        for name in ["ADS.example.com.", "aDs.ExAmPlE.cOm.", "x.Ads.Example.Com."] {
            let resp = run_handler(&st, &query(name, RecordType::A)).await;
            assert!(is_zero_ip_block(&resp), "{name} was not blocked");
        }
    }

    #[tokio::test]
    async fn handler_matches_punycode_entries_without_decoding() {
        // Lists store IDNs in their ASCII (xn--) form; the query must be
        // matched in that same form, not decoded to Unicode first.
        let st = test_state();
        {
            st.write()
                .await
                .blocklist
                .load("test", vec!["xn--bcher-kva.example".into()]);
        }
        let resp = run_handler(&st, &query("xn--BCHER-kva.example.", RecordType::A)).await;
        assert!(is_zero_ip_block(&resp));
    }

    #[tokio::test]
    async fn logged_domain_is_lowercase_ascii_without_escapes() {
        let st = test_state();
        {
            st.write()
                .await
                .blocklist
                .load("test", vec!["xn--bcher-kva.example".into()]);
        }
        let (tx, mut rx) = mpsc::channel(16);
        let src: SocketAddr = "192.168.1.42:5000".parse().unwrap();
        let q = query("XN--bcher-KVA.Example.", RecordType::A)
            .to_bytes()
            .unwrap();
        handle_query(src, &q, &st, &tx, &BlockMode::ZeroIp, true)
            .await
            .unwrap();
        assert_eq!(first_event(&mut rx).await.domain, "xn--bcher-kva.example");
    }

    /// UDP upstream that answers every query after `delay`.
    async fn slow_upstream(delay: std::time::Duration) -> SocketAddr {
        use hickory_proto::rr::rdata::A;
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                    continue;
                };
                let req = Message::from_bytes(&buf[..n]).unwrap();
                let sock = sock.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let mut r =
                        Message::new(0, MessageType::Query, hickory_proto::op::OpCode::Query);
                    r.metadata.id = req.metadata.id;
                    r.metadata.message_type = MessageType::Response;
                    r.add_queries(req.queries.to_vec());
                    let name = req.queries[0].name().clone();
                    r.add_answer(Record::from_rdata(name, 300, RData::A(A::new(1, 2, 3, 4))));
                    let _ = sock.send_to(&r.to_bytes().unwrap(), src).await;
                });
            }
        });
        addr
    }

    /// UDP upstream whose reply is built by `respond` from the request.
    async fn scripted_upstream(respond: fn(&Message) -> Message) -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                    continue;
                };
                let req = Message::from_bytes(&buf[..n]).unwrap();
                let mut r = respond(&req);
                r.metadata.id = req.metadata.id;
                r.metadata.message_type = MessageType::Response;
                if r.queries.is_empty() {
                    r.add_queries(req.queries.to_vec());
                }
                let _ = sock.send_to(&r.to_bytes().unwrap(), src).await;
            }
        });
        addr
    }

    fn soa(zone: &str, record_ttl: u32, minimum: u32) -> Record {
        use hickory_proto::rr::rdata::SOA;
        let z = Name::from_ascii(zone).unwrap();
        Record::from_rdata(
            z.clone(),
            record_ttl,
            RData::SOA(SOA::new(z.clone(), z, 1, 3600, 600, 86400, minimum)),
        )
    }

    async fn state_with_upstream(respond: fn(&Message) -> Message) -> Arc<RwLock<AppState>> {
        let up = scripted_upstream(respond).await;
        let st = test_state();
        {
            let mut s = st.write().await;
            s.ready = true;
            s.forwarder = Arc::new(crate::forwarder::Forwarder::with_upstreams(vec![up]));
        }
        st
    }

    /// Run one query, returning the reply and every message sent to Erlang.
    async fn run_collecting(
        st: &Arc<RwLock<AppState>>,
        q: &Message,
    ) -> (Message, Vec<WriterMessage>) {
        let (tx, mut rx) = mpsc::channel(64);
        let src: SocketAddr = "192.168.1.42:5000".parse().unwrap();
        let bytes = handle_query(
            src,
            &q.to_bytes().unwrap(),
            st,
            &tx,
            &BlockMode::ZeroIp,
            true,
        )
        .await
        .unwrap();
        drop(tx);
        let mut sent = Vec::new();
        while let Some(m) = rx.recv().await {
            sent.push(m);
        }
        (Message::from_bytes(&bytes).unwrap(), sent)
    }

    fn cache_stores(sent: &[WriterMessage]) -> usize {
        sent.iter()
            .filter(|m| matches!(m, WriterMessage::CacheStore(_)))
            .count()
    }

    // ── CNAME cloaking ──────────────────────────────────────────

    /// <query> CNAME <target>, <target> A 192.0.2.9: a tracker behind a
    /// first-party name.
    fn cloaked(req: &Message, target: &str) -> Message {
        use hickory_proto::rr::rdata::{A, CNAME};
        let mut r = Message::new(0, MessageType::Response, hickory_proto::op::OpCode::Query);
        let t = Name::from_ascii(target).unwrap();
        r.add_answer(Record::from_rdata(
            req.queries[0].name().clone(),
            300,
            RData::CNAME(CNAME(t.clone())),
        ));
        r.add_answer(Record::from_rdata(t, 300, RData::A(A::new(192, 0, 2, 9))));
        r
    }

    fn cloaked_to_tracker(req: &Message) -> Message {
        cloaked(req, "c1.Tracker.NET.")
    }

    fn events(sent: &[WriterMessage]) -> Vec<&QueryEvent> {
        sent.iter()
            .filter_map(|m| match m {
                WriterMessage::Event(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    fn cname_chain(targets: &[&str]) -> Message {
        let mut m = cloaked(&query("metrics.shop.com.", RecordType::A), targets[0]);
        for t in &targets[1..] {
            m.add_answer(Record::from_rdata(
                Name::from_ascii(targets[0]).unwrap(),
                300,
                RData::CNAME(hickory_proto::rr::rdata::CNAME(
                    Name::from_ascii(t).unwrap(),
                )),
            ));
        }
        m
    }

    #[test]
    fn blocked_cname_finds_any_target_in_the_chain() {
        let mut bl = crate::blocklist::Blocklist::new();
        bl.load("trackers", vec!["tracker.net".into()]);
        let al = crate::allowlist::Allowlist::new();
        assert_eq!(
            blocked_cname(
                &cname_chain(&["edge.cdn.example.", "c1.Tracker.NET."]),
                &bl,
                &al
            ),
            Some(("c1.tracker.net".into(), "trackers".into()))
        );
        assert_eq!(
            blocked_cname(&cname_chain(&["edge.cdn.example."]), &bl, &al),
            None
        );
        assert_eq!(
            blocked_cname(&query("metrics.shop.com.", RecordType::A), &bl, &al),
            None
        );
    }

    #[test]
    fn blocked_cname_honours_the_allowlist_and_list_exceptions() {
        let mut bl = crate::blocklist::Blocklist::new();
        bl.load(
            "trackers",
            vec!["tracker.net".into(), "@@safe.tracker.net".into()],
        );
        let mut al = crate::allowlist::Allowlist::new();
        al.load(vec!["c2.tracker.net".into()]);
        for t in ["a.safe.tracker.net.", "c2.tracker.net."] {
            assert_eq!(blocked_cname(&cname_chain(&[t]), &bl, &al), None, "{t}");
        }
    }

    #[tokio::test]
    async fn cname_into_a_blocklist_is_blocked_and_never_cached() {
        let st = state_with_upstream(cloaked_to_tracker).await;
        st.write()
            .await
            .blocklist
            .load("trackers", vec!["tracker.net".into()]);
        let (resp, sent) = run_collecting(&st, &query("metrics.shop.com.", RecordType::A)).await;
        assert!(is_zero_ip_block(&resp), "cloaked answer reached the client");
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(cache_stores(&sent), 0, "cloaked answer was propagated");
        let ev = events(&sent);
        assert_eq!(ev.len(), 1);
        assert!(matches!(ev[0].action, Action::BifrostBlock));
        assert_eq!(ev[0].domain, "metrics.shop.com");
        assert_eq!(ev[0].ede_code, Some(15));
        assert_eq!(ev[0].list_id.as_deref(), Some("trackers"));
        assert!(ev[0].latency_us.is_none());
        // The CNAME stays on the event so the query log shows WHY.
        assert!(ev[0]
            .response_records
            .as_ref()
            .is_some_and(|r| r.iter().any(|x| x.value.contains("racker"))));
        assert!(st.read().await.cache.lookup("metrics.shop.com:1").is_none());
    }

    #[tokio::test]
    async fn allowlisted_query_name_keeps_its_cloaked_answer() {
        let st = state_with_upstream(cloaked_to_tracker).await;
        {
            let mut s = st.write().await;
            s.blocklist.load("trackers", vec!["tracker.net".into()]);
            s.allowlist.load(vec!["metrics.shop.com".into()]);
        }
        let resp = run_handler(&st, &query("metrics.shop.com.", RecordType::A)).await;
        assert!(!is_zero_ip_block(&resp));
        assert_eq!(resp.answers.len(), 2);
    }

    #[tokio::test]
    async fn paused_protection_does_not_cname_block() {
        let st = state_with_upstream(cloaked_to_tracker).await;
        st.write()
            .await
            .blocklist
            .load("trackers", vec!["tracker.net".into()]);
        let (tx, _rx) = mpsc::channel(16);
        let bytes = handle_query(
            "192.168.1.42:5000".parse().unwrap(),
            &query("metrics.shop.com.", RecordType::A)
                .to_bytes()
                .unwrap(),
            &st,
            &tx,
            &BlockMode::ZeroIp,
            false,
        )
        .await
        .unwrap();
        assert_eq!(Message::from_bytes(&bytes).unwrap().answers.len(), 2);
    }

    /// An answer cached before its target was listed (or propagated from a
    /// peer) must not bypass the check: cache hits are checked too.
    #[tokio::test]
    async fn cached_cloaked_answer_is_blocked_on_hit() {
        let st = test_state();
        {
            let mut s = st.write().await;
            s.ready = true;
            let cached = cloaked_to_tracker(&query("metrics.shop.com.", RecordType::A));
            s.cache
                .insert("metrics.shop.com:1".into(), cached.to_bytes().unwrap(), 300);
            s.blocklist.load("trackers", vec!["tracker.net".into()]);
        }
        let (resp, sent) = run_collecting(&st, &query("metrics.shop.com.", RecordType::A)).await;
        assert!(is_zero_ip_block(&resp));
        let ev = events(&sent);
        assert_eq!(ev.len(), 1);
        assert!(matches!(ev[0].action, Action::BifrostBlock));
        assert_eq!(ev[0].list_id.as_deref(), Some("trackers"));
    }

    #[tokio::test]
    async fn servfail_is_neither_cached_nor_propagated() {
        let st = state_with_upstream(|_| {
            let mut r = Message::new(0, MessageType::Query, hickory_proto::op::OpCode::Query);
            r.metadata.response_code = ResponseCode::ServFail;
            r
        })
        .await;
        let (resp, sent) = run_collecting(&st, &query("flaky.example.", RecordType::A)).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        assert!(
            st.read().await.cache.lookup("flaky.example:1").is_none(),
            "SERVFAIL was cached"
        );
        assert_eq!(cache_stores(&sent), 0, "SERVFAIL was propagated to peers");
    }

    #[tokio::test]
    async fn refused_is_not_cached() {
        let st = state_with_upstream(|_| {
            let mut r = Message::new(0, MessageType::Query, hickory_proto::op::OpCode::Query);
            r.metadata.response_code = ResponseCode::Refused;
            r
        })
        .await;
        run_collecting(&st, &query("nope.example.", RecordType::A)).await;
        assert!(st.read().await.cache.lookup("nope.example:1").is_none());
    }

    #[tokio::test]
    async fn nxdomain_is_cached_for_the_soa_negative_ttl() {
        // RFC 2308: negative TTL = min(SOA record TTL, SOA MINIMUM).
        let st = state_with_upstream(|_| {
            let mut r = Message::new(0, MessageType::Query, hickory_proto::op::OpCode::Query);
            r.metadata.response_code = ResponseCode::NXDomain;
            r.add_authority(soa("example.", 900, 120));
            r
        })
        .await;
        let (_, sent) = run_collecting(&st, &query("missing.example.", RecordType::A)).await;
        let (_, ttl) = st
            .read()
            .await
            .cache
            .lookup("missing.example:1")
            .expect("NXDOMAIN not cached");
        assert!((110..=120).contains(&ttl), "negative ttl {ttl}");
        assert_eq!(cache_stores(&sent), 1);
    }

    #[tokio::test]
    async fn nodata_uses_the_soa_negative_ttl() {
        let st = state_with_upstream(|_| {
            let mut r = Message::new(0, MessageType::Query, hickory_proto::op::OpCode::Query);
            r.metadata.response_code = ResponseCode::NoError;
            r.add_authority(soa("example.", 45, 300));
            r
        })
        .await;
        run_collecting(&st, &query("v4only.example.", RecordType::AAAA)).await;
        let (_, ttl) = st
            .read()
            .await
            .cache
            .lookup("v4only.example:28")
            .expect("NODATA not cached");
        assert!((40..=45).contains(&ttl), "negative ttl {ttl}");
    }

    #[tokio::test]
    async fn negative_answer_without_soa_is_not_cached() {
        let st = state_with_upstream(|_| {
            let mut r = Message::new(0, MessageType::Query, hickory_proto::op::OpCode::Query);
            r.metadata.response_code = ResponseCode::NXDomain;
            r
        })
        .await;
        run_collecting(&st, &query("bare.example.", RecordType::A)).await;
        assert!(st.read().await.cache.lookup("bare.example:1").is_none());
    }

    #[tokio::test]
    async fn cache_hit_echoes_the_askers_question_case() {
        // 0x20 resolvers (e.g. Unbound use-caps-for-id) reject replies whose
        // question case differs from what they sent.
        let st = state_with_upstream(|req| {
            let mut r = Message::new(0, MessageType::Query, hickory_proto::op::OpCode::Query);
            let name = req.queries[0].name().clone();
            r.add_answer(Record::from_rdata(
                name,
                300,
                RData::A(hickory_proto::rr::rdata::A::new(1, 2, 3, 4)),
            ));
            r
        })
        .await;
        run_collecting(&st, &query("Example.ORG.", RecordType::A)).await;
        let (second, sent) = run_collecting(&st, &query("eXaMpLe.org.", RecordType::A)).await;
        assert!(
            sent.iter().any(
                |m| matches!(m, WriterMessage::Event(e) if matches!(e.action, Action::BifrostCache))
            ),
            "second query was not a cache hit"
        );
        assert_eq!(second.queries[0].name().to_ascii(), "eXaMpLe.org.");
        assert_eq!(second.metadata.id, 0x1234);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slow_upstream_does_not_stall_other_queries() {
        // tokio's RwLock is fair: if a forward holds a read guard across the
        // network await, one queued writer (a cache insert, any IPC message)
        // blocks every query behind it until the slow upstream answers.
        let up = slow_upstream(std::time::Duration::from_millis(1500)).await;
        let st = test_state();
        {
            let mut s = st.write().await;
            s.ready = true;
            s.forwarder = Arc::new(crate::forwarder::Forwarder::with_upstreams(vec![up]));
            s.blocklist.load("test", vec!["ads.example.com".into()]);
        }
        let st1 = st.clone();
        let slow =
            tokio::spawn(
                async move { run_handler(&st1, &query("slow.example.", RecordType::A)).await },
            );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let st2 = st.clone();
        tokio::spawn(async move {
            let _w = st2.write().await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let t = std::time::Instant::now();
        let resp = run_handler(&st, &query("ads.example.com.", RecordType::A)).await;
        let took = t.elapsed();
        assert!(is_zero_ip_block(&resp));
        assert!(
            took < std::time::Duration::from_millis(200),
            "blocked behind slow upstream for {took:?}"
        );
        slow.await.unwrap();
    }

    #[tokio::test]
    async fn client_outside_acl_is_refused_without_forwarding() {
        let st = test_state();
        {
            let mut s = st.write().await;
            s.ready = true;
            s.acl = crate::acl::Acl::from_cidrs(&["10.0.0.0/8".to_string()]);
        }
        // run_collecting's client is 192.168.1.42 — outside 10/8. No upstream
        // is configured, so any forwarding attempt would surface as SERVFAIL.
        let (resp, sent) = run_collecting(&st, &query("example.com.", RecordType::A)).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
        assert!(resp.answers.is_empty());
        assert!(
            sent.iter().any(
                |m| matches!(m, WriterMessage::Event(e) if matches!(e.action, Action::Refused))
            ),
            "refused query was not logged"
        );
    }

    #[tokio::test]
    async fn client_inside_acl_is_served() {
        let st = test_state();
        {
            let mut s = st.write().await;
            s.ready = true;
            s.acl = crate::acl::Acl::from_cidrs(&["192.168.0.0/16".to_string()]);
            s.blocklist.load("test", vec!["ads.example.com".into()]);
        }
        let (resp, _) = run_collecting(&st, &query("ads.example.com.", RecordType::A)).await;
        assert!(is_zero_ip_block(&resp));
    }

    async fn tcp_server(limits: TcpLimits) -> SocketAddr {
        let st = test_state();
        {
            let mut s = st.write().await;
            s.ready = true;
            s.block_mode = BlockMode::ZeroIp;
            s.blocklist.load("test", vec!["ads.example.com".into()]);
        }
        let (tx, rx) = mpsc::channel(64);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _keep = rx;
            serve_tcp(listener, st, tx, limits).await;
        });
        addr
    }

    /// True if the server closed the connection within `within`.
    async fn closed_within(
        stream: &mut tokio::net::TcpStream,
        within: std::time::Duration,
    ) -> bool {
        let mut b = [0u8; 1];
        matches!(
            tokio::time::timeout(within, stream.read(&mut b)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }

    #[tokio::test]
    async fn tcp_idle_connection_is_closed() {
        let ms = std::time::Duration::from_millis;
        let addr = tcp_server(TcpLimits {
            idle: ms(200),
            max_conns: 8,
        })
        .await;
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            closed_within(&mut c, ms(1500)).await,
            "idle connection held open"
        );
    }

    #[tokio::test]
    async fn tcp_stalled_mid_message_is_closed() {
        // Slowloris: announce a 100-byte message, then never send it.
        let ms = std::time::Duration::from_millis;
        let addr = tcp_server(TcpLimits {
            idle: ms(200),
            max_conns: 8,
        })
        .await;
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(&100u16.to_be_bytes()).await.unwrap();
        c.write_all(&[0u8; 10]).await.unwrap();
        assert!(
            closed_within(&mut c, ms(1500)).await,
            "stalled connection held open"
        );
    }

    #[tokio::test]
    async fn tcp_connections_beyond_limit_are_rejected() {
        let ms = std::time::Duration::from_millis;
        let addr = tcp_server(TcpLimits {
            idle: ms(5000),
            max_conns: 2,
        })
        .await;
        let _a = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _b = tokio::net::TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(ms(100)).await;
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            closed_within(&mut c, ms(1000)).await,
            "connection over the limit was served"
        );
    }

    #[tokio::test]
    async fn tcp_still_answers_queries_with_limits() {
        let ms = std::time::Duration::from_millis;
        let addr = tcp_server(TcpLimits {
            idle: ms(2000),
            max_conns: 2,
        })
        .await;
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        for _ in 0..3 {
            let q = query("ads.example.com.", RecordType::A).to_bytes().unwrap();
            c.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
            c.write_all(&q).await.unwrap();
            let mut len = [0u8; 2];
            c.read_exact(&mut len).await.unwrap();
            let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
            c.read_exact(&mut buf).await.unwrap();
            assert!(is_zero_ip_block(&Message::from_bytes(&buf).unwrap()));
        }
    }

    #[tokio::test]
    async fn handler_rewrite_beats_blocklist() {
        let st = test_state();
        {
            let mut s = st.write().await;
            s.blocklist.load("test", vec!["nas.home".into()]);
            s.rewrites
                .load(vec![("nas.home".into(), "192.168.1.5".into())]);
        }
        let resp = run_handler(&st, &query("nas.home.", RecordType::A)).await;
        // Rewrite wins: answers the IP, not a block.
        match resp.answers.first().map(|r| &r.data) {
            Some(RData::A(a)) => assert_eq!(a.0.to_string(), "192.168.1.5"),
            other => panic!("expected rewrite answer, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn handler_allowlist_bypasses_block() {
        let st = test_state();
        {
            let mut s = st.write().await;
            s.ready = true;
            s.blocklist.load("test", vec!["example.com".into()]);
            s.allowlist.load(vec!["example.com".into()]);
        }
        // Allowlisted + blocked + no upstreams => bypasses block, falls through
        // to forward which fails => SERVFAIL (via process). Key point: the
        // allowlist prevented a 0.0.0.0 block response.
        let (tx, _rx) = mpsc::channel(16);
        let src: SocketAddr = "192.168.1.42:5000".parse().unwrap();
        let bytes = process(
            src,
            &query("example.com.", RecordType::A).to_bytes().unwrap(),
            &st,
            &tx,
        )
        .await;
        let resp = Message::from_bytes(&bytes).unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
    }

    // ── TCP transport framing (length-prefixed, real socket) ──
    #[tokio::test]
    async fn tcp_length_prefixed_round_trip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let st = test_state();
        {
            let mut s = st.write().await;
            s.ready = true;
            s.block_mode = BlockMode::ZeroIp;
            s.blocklist.load("test", vec!["ads.example.com".into()]);
        }
        let (tx, _rx) = mpsc::channel(16);
        // Bind an ephemeral TCP listener running our handler.
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let bound = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let _ =
                handle_tcp_conn(stream, peer, &st, &tx, std::time::Duration::from_secs(10)).await;
        });

        // Client: send a length-prefixed blocked query, read length-prefixed reply.
        let q = query("ads.example.com.", RecordType::A).to_bytes().unwrap();
        let mut client = tokio::net::TcpStream::connect(bound).await.unwrap();
        client
            .write_all(&(q.len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(&q).await.unwrap();

        let mut len_buf = [0u8; 2];
        client.read_exact(&mut len_buf).await.unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        assert!(len > 0);
        let mut resp_buf = vec![0u8; len];
        client.read_exact(&mut resp_buf).await.unwrap();

        let resp = Message::from_bytes(&resp_buf).unwrap();
        // Blocked domain over TCP → 0.0.0.0, proving TCP framing + handler work.
        match resp.answers.first().map(|r| &r.data) {
            Some(RData::A(a)) => assert_eq!(a.0.to_string(), "0.0.0.0"),
            other => panic!("expected block over TCP, got {:?}", other),
        }
    }

    fn query_bytes(name: &str, edns_size: Option<u16>) -> Vec<u8> {
        let mut m = query(name, RecordType::A);
        m.metadata.message_type = MessageType::Query;
        if let Some(sz) = edns_size {
            let mut e = Edns::new();
            e.set_max_payload(sz);
            m.edns = Some(e);
        }
        m.to_bytes().unwrap()
    }

    #[test]
    fn small_response_passes_through_unchanged() {
        let q = query_bytes("example.com.", Some(4096));
        let resp = vec![0u8; 100];
        assert_eq!(truncate_for_client(&q, resp.clone()), resp);
    }

    #[test]
    fn oversized_response_truncated_with_tc_bit() {
        // No EDNS → 512-byte limit.
        let q = query_bytes("example.com.", None);
        let big = vec![0u8; 1000];
        let out = truncate_for_client(&q, big);
        assert!(out.len() <= 512);
        let msg = Message::from_bytes(&out).unwrap();
        assert!(msg.metadata.truncation);
        assert_eq!(msg.metadata.id, 0x1234);
    }

    #[test]
    fn respects_advertised_edns_size() {
        // Client advertises 2000; a 1500-byte answer fits, unchanged.
        let q = query_bytes("example.com.", Some(2000));
        let resp = vec![0u8; 1500];
        assert_eq!(truncate_for_client(&q, resp.clone()), resp);
    }
}
