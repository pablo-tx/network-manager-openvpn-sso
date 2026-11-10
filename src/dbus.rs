// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Pegasus Heavy Industries LLC

//! D-Bus interface implementing the NetworkManager VPN plugin API
//! (org.freedesktop.NetworkManager.VPN.Plugin)

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};
use zbus::zvariant::{OwnedValue, Value};
use zbus::{interface, Connection};

use crate::config::ConnectionConfig;
use crate::openvpn::{FailureKind, OpenVpnManager, VpnConfig, VpnEvent, VpnState};

/// D-Bus service name
const SERVICE_NAME: &str = "org.freedesktop.NetworkManager.openvpn-sso";

/// D-Bus object path
const OBJECT_PATH: &str = "/org/freedesktop/NetworkManager/VPN/Plugin";

/// D-Bus interface name
const PLUGIN_INTERFACE: &str = "org.freedesktop.NetworkManager.VPN.Plugin";

/// How long Disconnect waits for OpenVPN before aborting the session
const SESSION_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// NMVpnServiceState
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum NMVpnServiceState {
    Unknown = 0,
    Init = 1,
    Shutdown = 2,
    Starting = 3,
    Started = 4,
    Stopping = 5,
    Stopped = 6,
}

/// NMVpnPluginFailure
#[repr(u32)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum NMVpnPluginFailure {
    LoginFailed = 0,
    ConnectFailed = 1,
    BadIpConfig = 2,
}

/// A running connection
struct Session {
    stop: Arc<Notify>,
    task: JoinHandle<()>,
}

/// Shared plugin state
struct PluginState {
    /// State last reported to NetworkManager
    state: NMVpnServiceState,
    session: Option<Session>,
}

impl Default for PluginState {
    fn default() -> Self {
        Self {
            state: NMVpnServiceState::Init,
            session: None,
        }
    }
}

/// The VPN Plugin D-Bus object
pub struct VpnPlugin {
    state: Arc<Mutex<PluginState>>,
    /// Single event channel shared by all sessions, so events reach
    /// NetworkManager in the order they happened
    event_tx: mpsc::Sender<VpnEvent>,
}

#[interface(name = "org.freedesktop.NetworkManager.VPN.Plugin")]
impl VpnPlugin {
    /// Connect to VPN
    async fn connect(
        &mut self,
        connection: HashMap<String, HashMap<String, OwnedValue>>,
    ) -> zbus::fdo::Result<()> {
        info!("Connect called");

        let config = ConnectionConfig::from_nm_settings(&connection)
            .map_err(|e| zbus::fdo::Error::Failed(format!("{e:#}")))?;

        info!("Connecting to VPN: {} ({})", config.id, config.uuid);

        // supports-multiple-connections=false: only one tunnel at a time
        if stop_session(&self.state).await {
            warn!("Connect called while a session was active; replaced it");
        }

        self.event_tx
            .send(VpnEvent::State(VpnState::Connecting))
            .await
            .ok();

        let manager = OpenVpnManager::new(config, self.event_tx.clone());
        let stop = manager.stop_handle();
        let task = tokio::spawn(manager.run());
        self.state.lock().await.session = Some(Session { stop, task });

        Ok(())
    }

    /// Connect interactively (same as connect for us)
    async fn connect_interactive(
        &mut self,
        connection: HashMap<String, HashMap<String, OwnedValue>>,
        _details: HashMap<String, OwnedValue>,
    ) -> zbus::fdo::Result<()> {
        self.connect(connection).await
    }

    /// Check if secrets are needed. Authentication happens in the browser,
    /// so NetworkManager never has to prompt for anything.
    async fn need_secrets(
        &self,
        connection: HashMap<String, HashMap<String, OwnedValue>>,
    ) -> zbus::fdo::Result<String> {
        debug!("NeedSecrets called");
        // Validate early so NetworkManager reports a broken profile up front
        ConnectionConfig::from_nm_settings(&connection).map_err(|e| {
            error!("Failed to parse connection config: {e:#}");
            zbus::fdo::Error::Failed(format!("{e:#}"))
        })?;
        Ok(String::new())
    }

    /// Disconnect from VPN
    async fn disconnect(&mut self) -> zbus::fdo::Result<()> {
        info!("Disconnect called");
        stop_session(&self.state).await;
        // Normally the session already reported Stopped; this covers an
        // aborted session or a Disconnect without one. Duplicates are dropped.
        self.event_tx
            .send(VpnEvent::State(VpnState::Stopped))
            .await
            .ok();
        Ok(())
    }

    /// Set generic configuration
    async fn set_config(&self, _config: HashMap<String, OwnedValue>) -> zbus::fdo::Result<()> {
        debug!("SetConfig called");
        Ok(())
    }

    /// Set IPv4 configuration
    async fn set_ip4_config(&self, _config: HashMap<String, OwnedValue>) -> zbus::fdo::Result<()> {
        debug!("SetIp4Config called");
        Ok(())
    }

    /// Set IPv6 configuration
    async fn set_ip6_config(&self, _config: HashMap<String, OwnedValue>) -> zbus::fdo::Result<()> {
        debug!("SetIp6Config called");
        Ok(())
    }

    /// Called when new secrets are available
    async fn new_secrets(
        &self,
        _connection: HashMap<String, HashMap<String, OwnedValue>>,
    ) -> zbus::fdo::Result<()> {
        debug!("NewSecrets called");
        Ok(())
    }

    /// Set failure notification
    async fn set_failure(&self, reason: String) -> zbus::fdo::Result<()> {
        error!("SetFailure called: {}", reason);
        Ok(())
    }

    /// Current state property
    #[zbus(property, name = "State")]
    async fn vpn_state(&self) -> u32 {
        self.state.lock().await.state as u32
    }

    // Signals (StateChanged, Config, Ip4Config, Failure) are emitted by
    // process_vpn_events()
}

/// Stop the running session, if any, and wait for OpenVPN to exit.
/// Returns whether there was a session.
async fn stop_session(state: &Mutex<PluginState>) -> bool {
    // Take the session out first: never hold the lock across the wait
    let Some(session) = state.lock().await.session.take() else {
        return false;
    };

    session.stop.notify_one();
    let mut task = session.task;
    if tokio::time::timeout(SESSION_STOP_TIMEOUT, &mut task)
        .await
        .is_err()
    {
        warn!("VPN session did not stop within {SESSION_STOP_TIMEOUT:?}, aborting it");
        // Dropping the manager kills OpenVPN (kill_on_drop)
        task.abort();
        let _ = task.await;
    }
    true
}

/// NetworkManager service state for an OpenVPN connection state
fn service_state_for(state: VpnState) -> NMVpnServiceState {
    match state {
        // STARTED -> STARTING tells NetworkManager the plugin is reconnecting:
        // it keeps the connection and waits for a new Config/Ip4Config.
        VpnState::Connecting
        | VpnState::Authenticating
        | VpnState::GettingConfig
        | VpnState::Reconnecting => NMVpnServiceState::Starting,
        VpnState::Stopping => NMVpnServiceState::Stopping,
        VpnState::Stopped => NMVpnServiceState::Stopped,
    }
}

/// Forward VPN events to NetworkManager as D-Bus signals
async fn process_vpn_events(
    mut rx: mpsc::Receiver<VpnEvent>,
    state: Arc<Mutex<PluginState>>,
    connection: Connection,
) {
    while let Some(event) = rx.recv().await {
        match event {
            VpnEvent::State(vpn_state) => {
                debug!("VPN state: {:?}", vpn_state);
                set_service_state(&state, &connection, service_state_for(vpn_state)).await;
            }
            VpnEvent::Connected(vpn_config) => {
                let config = config_dict(&vpn_config);
                info!("Emitting Config signal: {:?}", config);
                if let Err(e) = emit_signal(&connection, "Config", &(config,)).await {
                    warn!("Failed to emit Config signal: {}", e);
                }

                let ip4_config = ip4_config_dict(&vpn_config);
                info!("Emitting Ip4Config signal: {:?}", ip4_config);
                if let Err(e) = emit_signal(&connection, "Ip4Config", &(ip4_config,)).await {
                    warn!("Failed to emit Ip4Config signal: {}", e);
                }

                set_service_state(&state, &connection, NMVpnServiceState::Started).await;
            }
            VpnEvent::Failed { reason, kind } => {
                error!("VPN failed: {}", reason);
                let code = match kind {
                    FailureKind::Login => NMVpnPluginFailure::LoginFailed,
                    FailureKind::Connect => NMVpnPluginFailure::ConnectFailed,
                } as u32;
                if let Err(e) = emit_signal(&connection, "Failure", &(code,)).await {
                    warn!("Failed to emit Failure signal: {}", e);
                }
            }
        }
    }
}

/// Record the new state and emit StateChanged if it changed
async fn set_service_state(
    state: &Mutex<PluginState>,
    connection: &Connection,
    new_state: NMVpnServiceState,
) {
    let old_state = std::mem::replace(&mut state.lock().await.state, new_state);
    if old_state == new_state {
        return;
    }
    info!("Plugin state {:?} -> {:?}", old_state, new_state);
    if let Err(e) = emit_signal(connection, "StateChanged", &(new_state as u32,)).await {
        warn!("Failed to emit StateChanged signal: {}", e);
    }
}

async fn emit_signal<B>(connection: &Connection, name: &str, body: &B) -> zbus::Result<()>
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    connection
        .emit_signal(None::<&str>, OBJECT_PATH, PLUGIN_INTERFACE, name, body)
        .await
}

/// IPv4 address as NetworkManager expects it on D-Bus: the in_addr_t value,
/// i.e. network byte order in memory. `u32::from(Ipv4Addr)` is host order and
/// came out byte-swapped on little-endian machines (10.8.0.8 -> 8.0.8.10).
fn ip4_to_nm(addr: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(addr.octets())
}

/// Body of the Config signal
fn config_dict(vpn_config: &VpnConfig) -> HashMap<&'static str, Value<'static>> {
    let mut config = HashMap::new();
    let tundev = vpn_config
        .tun_device
        .clone()
        .unwrap_or_else(|| "tun0".to_string());
    config.insert("tundev", Value::from(tundev));
    // External gateway (VPN server address); NetworkManager adds a host
    // route to it through the underlying connection.
    match vpn_config.remote_ip {
        Some(gateway) => {
            config.insert("gateway", Value::from(ip4_to_nm(gateway)));
        }
        None => warn!("VPN server address unknown; NetworkManager will reject the Config"),
    }
    config.insert("has-ip4", Value::from(true));
    config
}

/// Body of the Ip4Config signal
fn ip4_config_dict(vpn_config: &VpnConfig) -> HashMap<&'static str, Value<'static>> {
    let mut config = HashMap::new();
    if let Some(address) = vpn_config.local_ip {
        config.insert("address", Value::from(ip4_to_nm(address)));
        // The prefix comes from the interface OpenVPN configured; /32 is the
        // safe fallback that adds no subnet route.
        let prefix = u32::from(vpn_config.prefix.unwrap_or(32));
        config.insert("prefix", Value::from(prefix));
    }
    if let Some(peer) = vpn_config.peer_ip {
        config.insert("ptp", Value::from(ip4_to_nm(peer)));
    }
    if let Some(gateway) = vpn_config.remote_ip {
        config.insert("gateway", Value::from(ip4_to_nm(gateway)));
    }
    config
}

/// Run the D-Bus service until SIGTERM/SIGINT
pub async fn run_service() -> Result<()> {
    let connection = Connection::system()
        .await
        .map_err(|e| anyhow!("Failed to connect to system bus: {}", e))?;

    let state = Arc::new(Mutex::new(PluginState::default()));
    let (event_tx, event_rx) = mpsc::channel(100);
    tokio::spawn(process_vpn_events(
        event_rx,
        state.clone(),
        connection.clone(),
    ));

    let plugin = VpnPlugin {
        state: state.clone(),
        event_tx,
    };

    connection
        .object_server()
        .at(OBJECT_PATH, plugin)
        .await
        .map_err(|e| anyhow!("Failed to register object: {}", e))?;

    connection
        .request_name(SERVICE_NAME)
        .await
        .map_err(|e| anyhow!("Failed to request service name: {}", e))?;

    info!("D-Bus service registered as {}", SERVICE_NAME);
    info!("Listening on {}", OBJECT_PATH);

    wait_for_termination_signal().await?;

    // Do not leave an orphaned OpenVPN running with the tunnel up
    info!("Termination requested, stopping any active VPN session");
    stop_session(&state).await;
    Ok(())
}

async fn wait_for_termination_signal() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_addresses_use_network_byte_order() {
        let addr = Ipv4Addr::new(10, 8, 0, 8);
        // NetworkManager reads the u32's in-memory bytes as an in_addr_t
        assert_eq!(ip4_to_nm(addr).to_ne_bytes(), [10, 8, 0, 8]);
        #[cfg(target_endian = "little")]
        assert_eq!(ip4_to_nm(addr), 0x0800_080a);
    }

    #[test]
    fn reconnecting_maps_to_starting() {
        // NetworkManager only keeps the connection across a reconnect if the
        // plugin goes STARTED -> STARTING (not STOPPING, as before).
        assert_eq!(
            service_state_for(VpnState::Reconnecting),
            NMVpnServiceState::Starting
        );
        assert_eq!(NMVpnServiceState::Started as u32, 4);
    }

    #[test]
    fn ip4_config_uses_interface_prefix() {
        let config = VpnConfig {
            tun_device: Some("tun0".into()),
            local_ip: Some(Ipv4Addr::new(10, 8, 0, 8)),
            prefix: Some(24),
            peer_ip: None,
            remote_ip: Some(Ipv4Addr::new(52, 19, 23, 151)),
        };
        let dict = ip4_config_dict(&config);
        assert_eq!(
            dict["address"],
            Value::from(ip4_to_nm(Ipv4Addr::new(10, 8, 0, 8)))
        );
        assert_eq!(dict["prefix"], Value::from(24u32));
        assert_eq!(
            dict["gateway"],
            Value::from(ip4_to_nm(Ipv4Addr::new(52, 19, 23, 151)))
        );
        assert!(!dict.contains_key("int-gw"));
    }
}
