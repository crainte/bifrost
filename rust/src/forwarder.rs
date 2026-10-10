use std::future::{poll_fn, Future};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;
use tokio::sync::Semaphore;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{timeout, timeout_at, Instant};

/// Per-upstream query timeout. On timeout or error, we fail over to the next
/// upstream rather than hanging or failing the whole query.
const UPSTREAM_TIMEOUT: Duration = Duration::from_millis(2000);

/// After a failure an upstream is tried last for this long, so a dead resolver
/// does not cost every query a full timeout. It is still tried when nothing
/// healthier is left, so a recovered upstream comes back immediately.
const HOLD_DOWN: Duration = Duration::from_secs(30);

type Error = Box<dyn std::error::Error + Send + Sync>;

/// TC (truncation) bit lives in the second flags byte of the 12-byte DNS
/// header: byte 2, mask 0x02. A response shorter than the header can't be
/// truncated (and isn't a valid answer anyway).
fn is_truncated(msg: &[u8]) -> bool {
    msg.len() >= 3 && msg[2] & 0x02 != 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    Sequential,
    Parallel,
    Fastest,
}

static NETWORK_LIMIT: Semaphore = Semaphore::const_new(512);

struct Upstream {
    addr: SocketAddr,
    /// Milliseconds since `Forwarder::epoch` until which this upstream is held
    /// down. 0 = healthy.
    down_until_ms: AtomicU64,
    latency_us: AtomicU64,
}

pub struct Forwarder {
    upstreams: Vec<Upstream>,
    counter: AtomicUsize,
    timeout: Duration,
    epoch: Instant,
    primary_count: usize,
    strategy: Strategy,
    deadline: Duration,
    limit: Semaphore,
}

impl Forwarder {
    pub fn new() -> Self {
        Self::with_timeout(Vec::new(), UPSTREAM_TIMEOUT)
    }

    pub fn with_upstreams(upstreams: Vec<SocketAddr>) -> Self {
        Self::with_timeout(upstreams, UPSTREAM_TIMEOUT)
    }

    pub fn with_timeout(upstreams: Vec<SocketAddr>, timeout: Duration) -> Self {
        let count = upstreams.len();
        Self::configured(
            upstreams,
            vec![],
            Strategy::Sequential,
            timeout,
            timeout.saturating_mul((count.max(1) * 2) as u32),
        )
    }

    pub fn configured(
        primary: Vec<SocketAddr>,
        fallback: Vec<SocketAddr>,
        strategy: Strategy,
        timeout: Duration,
        deadline: Duration,
    ) -> Self {
        let primary_count = primary.len();
        Self {
            upstreams: primary
                .into_iter()
                .chain(fallback)
                .collect::<Vec<_>>()
                .into_iter()
                .map(|addr| Upstream {
                    addr,
                    down_until_ms: AtomicU64::new(0),
                    latency_us: AtomicU64::new(0),
                })
                .collect(),
            counter: AtomicUsize::new(0),
            timeout,
            epoch: Instant::now(),
            primary_count,
            strategy,
            deadline,
            limit: Semaphore::new(64),
        }
    }

    pub fn upstream_count(&self) -> usize {
        self.upstreams.len()
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Round-robin order, with upstreams in hold-down moved to the back.
    fn attempt_order<'a>(&self, entries: &'a [Upstream]) -> Vec<&'a Upstream> {
        let n = entries.len();
        if n == 0 {
            return vec![];
        }
        let tick = self.counter.fetch_add(1, Ordering::Relaxed);
        let start = tick % n;
        let now = self.now_ms();
        let (mut healthy, down): (Vec<&Upstream>, Vec<&Upstream>) = (0..n)
            .map(|i| &entries[(start + i) % n])
            .partition(|u| u.down_until_ms.load(Ordering::Relaxed) <= now);
        if self.strategy == Strategy::Fastest && !tick.is_multiple_of(16) {
            healthy.sort_by_key(|u| u.latency_us.load(Ordering::Relaxed));
        }
        healthy.extend(down);
        healthy
    }

    /// Forward a query, trying each upstream until one returns a reply that
    /// matches it. Returns the response (carrying the client's original ID)
    /// and the latency of the upstream that answered. Errors only if EVERY
    /// upstream fails.
    pub async fn forward(&self, query: &[u8]) -> Result<(Vec<u8>, u64), Error> {
        if self.upstreams.is_empty() {
            return Err("no upstreams configured".into());
        }
        let request = Message::from_bytes(query)?;
        let deadline = Instant::now() + self.deadline;
        timeout_at(deadline, async {
            let mut last_err: Error = "no upstreams attempted".into();
            for entries in [
                &self.upstreams[..self.primary_count],
                &self.upstreams[self.primary_count..],
            ] {
                let order = self.attempt_order(entries);
                if self.strategy == Strategy::Parallel {
                    let mut pending: Vec<_> = order
                        .into_iter()
                        .map(|u| Some(Box::pin(self.attempt(query, &request, u, deadline))))
                        .collect();
                    while pending.iter().any(Option::is_some) {
                        let result = poll_fn(|cx| {
                            for item in &mut pending {
                                if let Some(future) = item {
                                    if let Poll::Ready(result) = future.as_mut().poll(cx) {
                                        *item = None;
                                        return Poll::Ready(result);
                                    }
                                }
                            }
                            Poll::Pending
                        })
                        .await;
                        match result {
                            Ok(answer) => return Ok(answer),
                            Err(e) => last_err = e,
                        }
                    }
                } else {
                    for upstream in order {
                        match self.attempt(query, &request, upstream, deadline).await {
                            Ok(answer) => return Ok(answer),
                            Err(e) => last_err = e,
                        }
                    }
                }
            }
            Err(last_err)
        })
        .await
        .map_err(|_| -> Error { "query deadline exceeded".into() })?
    }

    async fn attempt(
        &self,
        query: &[u8],
        request: &Message,
        upstream: &Upstream,
        total_deadline: Instant,
    ) -> Result<(Vec<u8>, u64), Error> {
        let _group = timeout_at(total_deadline, self.limit.acquire()).await??;
        let _global = timeout_at(total_deadline, NETWORK_LIMIT.acquire()).await??;
        let deadline = total_deadline.min(Instant::now() + self.timeout);
        let result = match timeout_at(deadline, self.query_one(query, request, upstream.addr)).await
        {
            Ok(Ok(answer)) => {
                if Message::from_bytes(&answer.0)?.response_code()
                    == hickory_proto::op::ResponseCode::ServFail
                {
                    Err("upstream returned SERVFAIL".into())
                } else {
                    Ok(answer)
                }
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err("upstream attempt timed out".into()),
        };
        match &result {
            Ok((_, elapsed)) => {
                upstream.down_until_ms.store(0, Ordering::Relaxed);
                let old = upstream.latency_us.load(Ordering::Relaxed);
                upstream.latency_us.store(
                    if old == 0 {
                        *elapsed
                    } else {
                        old * 7 / 8 + elapsed / 8
                    },
                    Ordering::Relaxed,
                );
            }
            Err(_) => upstream.down_until_ms.store(
                self.now_ms() + HOLD_DOWN.as_millis() as u64,
                Ordering::Relaxed,
            ),
        }
        result
    }

    async fn query_one(
        &self,
        query: &[u8],
        request: &Message,
        upstream: SocketAddr,
    ) -> Result<(Vec<u8>, u64), Error> {
        let (txid, outbound) = with_fresh_id(query);
        let bind: SocketAddr = if upstream.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()?;
        let socket = UdpSocket::bind(bind).await?;
        // Connected: the kernel drops datagrams from any other address/port, so
        // only the upstream itself can answer this socket.
        socket.connect(upstream).await?;
        let start = Instant::now();
        let deadline = start + self.timeout;
        socket.send(&outbound).await?;

        let mut buf = vec![0u8; 4096];
        let resp = loop {
            let n = match timeout_at(deadline, socket.recv(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Err(format!("upstream {} timed out", upstream).into()),
            };
            // Anything that is not the answer to THIS question with THIS id is
            // ignored rather than accepted; keep waiting for the real one.
            if matches_request(&buf[..n], txid, request) {
                break buf[..n].to_vec();
            }
        };

        // If the UDP answer is truncated, the real answer is larger than what
        // fit. Re-query the same upstream over TCP to get the full response.
        let resp = if is_truncated(&resp) {
            self.query_tcp(query, request, upstream).await?
        } else {
            resp
        };
        let latency_us = start.elapsed().as_micros() as u64;
        Ok((restore_id(resp, query), latency_us))
    }

    /// DNS over TCP: 2-byte big-endian length prefix + message, both directions.
    async fn query_tcp(
        &self,
        query: &[u8],
        request: &Message,
        upstream: SocketAddr,
    ) -> Result<Vec<u8>, Error> {
        let (txid, outbound) = with_fresh_id(query);
        let fut = async {
            let mut stream = TcpStream::connect(upstream).await?;
            let len = (outbound.len() as u16).to_be_bytes();
            stream.write_all(&len).await?;
            stream.write_all(&outbound).await?;

            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            let mut resp = vec![0u8; resp_len];
            stream.read_exact(&mut resp).await?;
            Ok::<Vec<u8>, Error>(resp)
        };
        let resp = match timeout(self.timeout, fut).await {
            Ok(r) => r?,
            Err(_) => return Err(format!("upstream {} TCP timed out", upstream).into()),
        };
        if matches_request(&resp, txid, request) {
            Ok(resp)
        } else {
            Err(format!("upstream {} TCP answer does not match query", upstream).into())
        }
    }
}

/// Copy of the query with an unpredictable transaction id.
fn with_fresh_id(query: &[u8]) -> (u16, Vec<u8>) {
    let txid: u16 = rand::random();
    let mut out = query.to_vec();
    out[..2].copy_from_slice(&txid.to_be_bytes());
    (txid, out)
}

/// Put the client's original id back on the upstream's response.
fn restore_id(mut resp: Vec<u8>, query: &[u8]) -> Vec<u8> {
    resp[..2].copy_from_slice(&query[..2]);
    resp
}

/// A reply is accepted only if it parses, is a response, carries our id, and
/// echoes exactly the question we asked.
fn matches_request(resp: &[u8], txid: u16, request: &Message) -> bool {
    if resp.len() < 2 || u16::from_be_bytes([resp[0], resp[1]]) != txid {
        return false;
    }
    match Message::from_bytes(resp) {
        Ok(m) => {
            m.message_type() == hickory_proto::op::MessageType::Response
                && m.queries().len() == request.queries().len()
                && m.queries().iter().zip(request.queries()).all(|(a, b)| {
                    a.name().eq_case(b.name())
                        && a.query_type() == b.query_type()
                        && a.query_class() == b.query_class()
                })
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use std::sync::{Arc, Mutex};

    const CLIENT_ID: u16 = 0x1234;

    fn query(name: &str) -> Vec<u8> {
        let mut m = Message::new();
        m.set_id(CLIENT_ID);
        m.set_recursion_desired(true);
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        m.to_bytes().unwrap()
    }

    /// An answer to `query_bytes`, optionally lying about the ID or question.
    fn answer(
        query_bytes: &[u8],
        ip: [u8; 4],
        id: Option<u16>,
        qname: Option<&str>,
        tc: bool,
    ) -> Vec<u8> {
        let req = Message::from_bytes(query_bytes).unwrap();
        let mut r = Message::new();
        r.set_id(id.unwrap_or(req.id()));
        r.set_message_type(MessageType::Response);
        r.set_response_code(ResponseCode::NoError);
        r.set_truncated(tc);
        let name = match qname {
            Some(n) => Name::from_ascii(n).unwrap(),
            None => req.queries()[0].name().clone(),
        };
        r.add_query(Query::query(name.clone(), req.queries()[0].query_type()));
        if !tc {
            r.add_answer(Record::from_rdata(
                name,
                300,
                RData::A(A::new(ip[0], ip[1], ip[2], ip[3])),
            ));
        }
        r.to_bytes().unwrap()
    }

    fn answer_ip(resp: &[u8]) -> String {
        let m = Message::from_bytes(resp).unwrap();
        match m.answers().first().and_then(|r| r.data()) {
            Some(RData::A(a)) => a.0.to_string(),
            other => panic!("no A answer: {other:?}"),
        }
    }

    /// A UDP upstream that answers every query with `ip`, recording the
    /// transaction IDs it saw.
    async fn upstream(ip: [u8; 4]) -> (SocketAddr, Arc<Mutex<Vec<u16>>>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                if let Ok((n, src)) = sock.recv_from(&mut buf).await {
                    seen2
                        .lock()
                        .unwrap()
                        .push(u16::from_be_bytes([buf[0], buf[1]]));
                    let _ = sock
                        .send_to(&answer(&buf[..n], ip, None, None, false), src)
                        .await;
                }
            }
        });
        (addr, seen)
    }

    /// An upstream that never answers (but does accept packets).
    async fn blackhole() -> SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let _ = sock.recv_from(&mut buf).await;
            }
        });
        addr
    }

    fn fwd(upstreams: Vec<SocketAddr>) -> Forwarder {
        Forwarder::with_timeout(upstreams, Duration::from_millis(300))
    }

    #[tokio::test]
    async fn total_deadline_bounds_multiple_dead_upstreams() {
        let a = blackhole().await;
        let b = blackhole().await;
        let f = Forwarder::configured(
            vec![a, b],
            vec![],
            Strategy::Sequential,
            Duration::from_millis(200),
            Duration::from_millis(250),
        );
        let start = Instant::now();
        assert!(f.forward(&query("deadline.example.")).await.is_err());
        assert!(start.elapsed() < Duration::from_millis(380));
    }

    #[tokio::test]
    async fn fallback_is_used_after_primary_failure() {
        let dead = blackhole().await;
        let (good, seen) = upstream([2, 3, 4, 5]).await;
        let f = Forwarder::configured(
            vec![dead],
            vec![good],
            Strategy::Sequential,
            Duration::from_millis(100),
            Duration::from_secs(1),
        );
        let (resp, _) = f.forward(&query("fallback.example.")).await.unwrap();
        assert_eq!(answer_ip(&resp), "2.3.4.5");
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn parallel_does_not_wait_for_silent_primary() {
        let dead = blackhole().await;
        let (good, _) = upstream([2, 3, 4, 5]).await;
        let f = Forwarder::configured(
            vec![dead, good],
            vec![],
            Strategy::Parallel,
            Duration::from_secs(1),
            Duration::from_secs(2),
        );
        let start = Instant::now();
        let (resp, _) = f.forward(&query("parallel.example.")).await.unwrap();
        assert_eq!(answer_ip(&resp), "2.3.4.5");
        assert!(start.elapsed() < Duration::from_millis(300));
    }

    #[tokio::test]
    async fn fastest_explores_and_keeps_healthy_answers() {
        let (a, seen_a) = upstream([1, 1, 1, 1]).await;
        let (b, seen_b) = upstream([2, 2, 2, 2]).await;
        let f = Forwarder::configured(
            vec![a, b],
            vec![],
            Strategy::Fastest,
            Duration::from_millis(200),
            Duration::from_secs(1),
        );
        for _ in 0..40 {
            f.forward(&query("fastest.example.")).await.unwrap();
        }
        assert!(!seen_a.lock().unwrap().is_empty());
        assert!(!seen_b.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn servfail_retries_but_nxdomain_is_terminal() {
        for (rcode, expected) in [
            (hickory_proto::op::ResponseCode::ServFail, 1),
            (hickory_proto::op::ResponseCode::NXDomain, 0),
        ] {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let (n, src) = socket.recv_from(&mut buf).await.unwrap();
                let mut resp =
                    Message::from_bytes(&answer(&buf[..n], [0; 4], None, None, false)).unwrap();
                resp.set_response_code(rcode);
                socket
                    .send_to(&resp.to_bytes().unwrap(), src)
                    .await
                    .unwrap();
            });
            let (good, seen) = upstream([2, 3, 4, 5]).await;
            let f = Forwarder::configured(
                vec![addr],
                vec![good],
                Strategy::Sequential,
                Duration::from_millis(200),
                Duration::from_secs(1),
            );
            f.forward(&query("rcode.example.")).await.unwrap();
            assert_eq!(seen.lock().unwrap().len(), expected);
        }
    }

    #[tokio::test]
    async fn single_healthy_upstream_answers() {
        let (up, _) = upstream([1, 1, 1, 1]).await;
        let (resp, _) = fwd(vec![up]).forward(&query("a.example.")).await.unwrap();
        assert_eq!(answer_ip(&resp), "1.1.1.1");
    }

    #[tokio::test]
    async fn response_carries_the_clients_id() {
        let (up, _) = upstream([1, 1, 1, 1]).await;
        let (resp, _) = fwd(vec![up]).forward(&query("a.example.")).await.unwrap();
        assert_eq!(Message::from_bytes(&resp).unwrap().id(), CLIENT_ID);
    }

    #[tokio::test]
    async fn upstream_sees_randomised_transaction_ids() {
        // Forwarding the client's own ID lets anyone who can guess it (often 0
        // or sequential) forge answers. Each upstream query gets a fresh one.
        let (up, seen) = upstream([1, 1, 1, 1]).await;
        let f = fwd(vec![up]);
        for _ in 0..20 {
            f.forward(&query("a.example.")).await.unwrap();
        }
        let ids = seen.lock().unwrap().clone();
        assert_eq!(ids.len(), 20);
        assert!(
            ids.iter().any(|&id| id != CLIENT_ID),
            "client id forwarded verbatim: {ids:?}"
        );
        let distinct: std::collections::HashSet<_> = ids.iter().collect();
        assert!(distinct.len() > 1, "ids not randomised: {ids:?}");
    }

    #[tokio::test]
    async fn ignores_forged_reply_from_another_address() {
        // A real upstream that answers late, and an attacker who races it with
        // a well-formed forged answer from a different port.
        let real = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let real_addr = real.local_addr().unwrap();
        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, victim) = real.recv_from(&mut buf).await.unwrap();
            let q = buf[..n].to_vec();
            attacker
                .send_to(&answer(&q, [6, 6, 6, 6], None, None, false), victim)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            real.send_to(&answer(&q, [1, 2, 3, 4], None, None, false), victim)
                .await
                .unwrap();
        });
        let (resp, _) = fwd(vec![real_addr])
            .forward(&query("bank.example."))
            .await
            .unwrap();
        assert_eq!(answer_ip(&resp), "1.2.3.4");
    }

    #[tokio::test]
    async fn ignores_reply_with_wrong_id_or_question() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, src) = sock.recv_from(&mut buf).await.unwrap();
            let q = buf[..n].to_vec();
            let real_id = u16::from_be_bytes([q[0], q[1]]);
            let bad_id = answer(&q, [6, 6, 6, 6], Some(real_id.wrapping_add(1)), None, false);
            let bad_q = answer(&q, [7, 7, 7, 7], None, Some("other.example."), false);
            sock.send_to(&bad_id, src).await.unwrap();
            sock.send_to(&bad_q, src).await.unwrap();
            sock.send_to(&[0xde, 0xad], src).await.unwrap();
            sock.send_to(&answer(&q, [1, 2, 3, 4], None, None, false), src)
                .await
                .unwrap();
        });
        let (resp, _) = fwd(vec![addr])
            .forward(&query("bank.example."))
            .await
            .unwrap();
        assert_eq!(answer_ip(&resp), "1.2.3.4");
    }

    #[tokio::test]
    async fn fails_over_from_dead_to_healthy() {
        let dead = blackhole().await;
        let (up, _) = upstream([9, 9, 9, 9]).await;
        let (resp, _) = fwd(vec![dead, up])
            .forward(&query("a.example."))
            .await
            .unwrap();
        assert_eq!(answer_ip(&resp), "9.9.9.9");
    }

    #[tokio::test]
    async fn skips_an_upstream_that_just_failed() {
        // After one timeout, a dead upstream must not cost every later query
        // another timeout while a healthy one is available.
        let dead = blackhole().await;
        let (up, _) = upstream([9, 9, 9, 9]).await;
        let f = fwd(vec![dead, up]);
        f.forward(&query("warmup.example.")).await.unwrap();
        let start = Instant::now();
        for i in 0..6 {
            f.forward(&query(&format!("q{i}.example."))).await.unwrap();
        }
        assert!(
            start.elapsed() < Duration::from_millis(250),
            "dead upstream still in rotation: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn still_tries_upstreams_marked_down_when_none_are_healthy() {
        // A briefly-dead upstream that recovers must be retried rather than
        // the resolver refusing all service until the hold-down expires.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let _ = sock.recv_from(&mut buf).await;
            loop {
                if let Ok((n, src)) = sock.recv_from(&mut buf).await {
                    let _ = sock
                        .send_to(&answer(&buf[..n], [5, 5, 5, 5], None, None, false), src)
                        .await;
                }
            }
        });
        let f = fwd(vec![addr]);
        assert!(f.forward(&query("first.example.")).await.is_err());
        let (resp, _) = f.forward(&query("second.example.")).await.unwrap();
        assert_eq!(answer_ip(&resp), "5.5.5.5");
    }

    #[tokio::test]
    async fn errors_when_all_upstreams_dead() {
        let f = fwd(vec![blackhole().await, blackhole().await]);
        assert!(f.forward(&query("a.example.")).await.is_err());
    }

    #[tokio::test]
    async fn no_upstreams_errors() {
        assert!(Forwarder::new()
            .forward(&query("a.example."))
            .await
            .is_err());
    }

    #[test]
    fn truncation_bit_detected() {
        let q = query("a.example.");
        assert!(is_truncated(&answer(&q, [0; 4], None, None, true)));
        assert!(!is_truncated(&answer(&q, [0; 4], None, None, false)));
        assert!(!is_truncated(&[0, 0]));
    }

    /// UDP answers truncated; TCP on the same port answers in full.
    async fn truncating_upstream(tcp_ip: [u8; 4], tcp_id_offset: u16) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let udp = UdpSocket::bind(addr).await.unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                if let Ok((n, src)) = udp.recv_from(&mut buf).await {
                    let _ = udp
                        .send_to(&answer(&buf[..n], [0; 4], None, None, true), src)
                        .await;
                }
            }
        });
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut len_buf = [0u8; 2];
                let _ = stream.read_exact(&mut len_buf).await;
                let mut q = vec![0u8; u16::from_be_bytes(len_buf) as usize];
                let _ = stream.read_exact(&mut q).await;
                let id = u16::from_be_bytes([q[0], q[1]]).wrapping_add(tcp_id_offset);
                let full = answer(&q, tcp_ip, Some(id), None, false);
                let _ = stream.write_all(&(full.len() as u16).to_be_bytes()).await;
                let _ = stream.write_all(&full).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn retries_tcp_when_udp_truncated() {
        let addr = truncating_upstream([4, 4, 4, 4], 0).await;
        let (resp, _) = fwd(vec![addr])
            .forward(&query("big.example."))
            .await
            .unwrap();
        assert_eq!(answer_ip(&resp), "4.4.4.4");
        assert_eq!(Message::from_bytes(&resp).unwrap().id(), CLIENT_ID);
    }

    #[tokio::test]
    async fn rejects_tcp_answer_with_wrong_id() {
        let addr = truncating_upstream([6, 6, 6, 6], 1).await;
        let (good, _) = upstream([7, 7, 7, 7]).await;
        let (resp, _) = fwd(vec![addr, good])
            .forward(&query("big.example."))
            .await
            .unwrap();
        assert_eq!(answer_ip(&resp), "7.7.7.7");
    }

    #[tokio::test]
    async fn tcp_fallback_timeout_fails_over() {
        // Truncates over UDP but never accepts TCP.
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bad = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                if let Ok((n, src)) = udp.recv_from(&mut buf).await {
                    let _ = udp
                        .send_to(&answer(&buf[..n], [0; 4], None, None, true), src)
                        .await;
                }
            }
        });
        let (good, _) = upstream([7, 7, 7, 7]).await;
        let (resp, _) = fwd(vec![bad, good])
            .forward(&query("a.example."))
            .await
            .unwrap();
        assert_eq!(answer_ip(&resp), "7.7.7.7");
    }
}
