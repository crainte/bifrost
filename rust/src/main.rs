mod acl;
mod allowlist;
mod blocklist;
mod cache;
mod client_blocks;
mod events;
mod forwarder;
mod ipc;
mod listener;
mod rewrites;
mod routing;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info};

use blocklist::Blocklist;
use cache::Cache;
use forwarder::Forwarder;
use ipc::WriterMessage;

#[derive(Clone, Debug)]
pub enum BlockMode {
    ZeroIp,
    NXDomain,
    Refused,
    CustomIp(IpAddr),
}

pub struct AppState {
    pub ready: bool,
    pub rewrites: rewrites::Rewrites,
    pub blocklist: Blocklist,
    pub allowlist: allowlist::Allowlist,
    pub client_blocks: client_blocks::ClientBlocks,
    pub cache: Cache,
    /// Behind an Arc so the hot path can clone it out of the state lock and
    /// await the network without holding the lock.
    pub forwarder: Arc<Forwarder>,
    pub routing: Option<Arc<routing::Routing>>,
    pub settings_revision: u64,
    pub settings_fingerprint: String,
    pub policy_generation: u64,
    pub block_mode: BlockMode,
    pub protection_enabled: bool,
    pub acl: acl::Acl,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            ready: false,
            blocklist: Blocklist::new(),
            rewrites: rewrites::Rewrites::new(),
            allowlist: allowlist::Allowlist::new(),
            client_blocks: client_blocks::ClientBlocks::new(),
            cache: Cache::new(100000),
            forwarder: Arc::new(Forwarder::new()),
            routing: None,
            settings_revision: 0,
            settings_fingerprint: String::new(),
            policy_generation: 0,
            block_mode: BlockMode::NXDomain,
            protection_enabled: true,
            acl: acl::Acl::allow_all(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bifrost_resolver=info".into()),
        )
        .init();

    info!("starting Bifrost DNS hot path");

    let state = Arc::new(RwLock::new(AppState::new()));

    let (event_tx, event_rx) = mpsc::channel::<WriterMessage>(4096);
    let (ready_tx, mut ready_rx) = mpsc::channel::<()>(1);

    let socket_path =
        std::env::var("BIFROST_IPC_PATH").unwrap_or_else(|_| "/run/bifrost/ipc.sock".to_string());

    tokio::spawn(ipc::run(socket_path, event_rx, ready_tx, state.clone()));

    let listen_addr: SocketAddr = std::env::var("BIFROST_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:5454".to_string())
        .parse()
        .expect("invalid BIFROST_LISTEN_ADDR");

    let udp_state = state.clone();
    let udp_tx = event_tx.clone();
    let udp_addr = listen_addr;
    let listener_handle = tokio::spawn(async move {
        if let Err(e) = listener::run_udp(udp_state, udp_tx, udp_addr).await {
            panic!("UDP listener failed: {e}");
        }
    });

    let tcp_state = state.clone();
    let tcp_tx = event_tx.clone();
    let _tcp_handle = tokio::spawn(async move {
        if let Err(e) = listener::run_tcp(tcp_state, tcp_tx, listen_addr).await {
            error!("TCP listener failed: {e}");
        }
    });

    match ready_rx.recv().await {
        Some(()) => {
            info!("reload_complete received, marking ready");
            let mut s = state.write().await;
            s.ready = true;
        }
        None => {
            error!("ready channel closed without reload_complete — IPC task died");
            std::process::exit(1);
        }
    }

    info!("Bifrost DNS hot path ready — accepting queries");

    listener_handle.await.expect("listener task panicked");
    Ok(())
}
