// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

//! OpenVPN process management and management interface protocol.
//!
//! The module has two halves:
//!
//! * [`Protocol`] is a pure state machine that turns management-interface
//!   lines into [`Action`]s. Every authentication decision lives here, so the
//!   connect / re-authenticate / reconnect flow can be unit tested against
//!   real OpenVPN transcripts.
//! * [`OpenVpnManager`] owns the OpenVPN process and the management socket
//!   and carries out those actions: socket writes, browser launch, token
//!   cache, and events for the D-Bus layer.
//!
//! One OpenVPN process lives for the whole connection. OpenVPN restarts
//! itself internally (ping-restart, network change, rejected auth-token) and
//! the protocol follows along: it releases every management hold, answers
//! every credential request, and re-runs SSO in the browser when the server
//! asks for it again.

use std::io::Write as _;
use std::net::Ipv4Addr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::ConnectionConfig;
use crate::ovpn::{self, ConfigFile, Prepared};
use crate::{oauth, secrets};

/// Runtime directory for management sockets. Lives under /run instead of
/// /tmp because SELinux confines openvpn and denies sockets in /tmp.
const RUNTIME_DIR: &str = "/run/nm-openvpn-sso";

/// Give up after this many consecutive SSO rounds fail without connecting,
/// so an unattended machine does not open browser tabs forever.
const MAX_SSO_FAILURES: u32 = 3;

/// How long OpenVPN gets to exit after SIGTERM before it is killed.
const OPENVPN_EXIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Assumed lifetime of a cached server auth-token. The server does not
/// announce the real lifetime; a stale token only costs one rejected attempt.
const CACHED_TOKEN_TTL_SECS: i64 = 24 * 60 * 60;

/// Events reported to the D-Bus layer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VpnEvent {
    /// Connection progress
    State(VpnState),
    /// Tunnel is up (initially or again after a reconnect)
    Connected(VpnConfig),
    /// The connection failed for good; `State(Stopped)` follows
    Failed { reason: String, kind: FailureKind },
}

/// Why a connection failed, mapped to NMVpnPluginFailure
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    Login,
    Connect,
}

/// Connection progress as seen by OpenVPN
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnState {
    /// Process starting, resolving or contacting the server
    Connecting,
    /// TLS handshake or authentication in progress (including SSO pending)
    Authenticating,
    /// Authenticated, receiving the pushed configuration
    GettingConfig,
    /// The tunnel was up and OpenVPN is re-establishing it
    Reconnecting,
    /// Shutting down
    Stopping,
    /// Process gone
    Stopped,
}

/// Tunnel parameters reported to NetworkManager
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VpnConfig {
    /// Tunnel interface name (e.g. tun0)
    pub tun_device: Option<String>,
    /// Address assigned to us inside the tunnel
    pub local_ip: Option<Ipv4Addr>,
    /// Prefix length of `local_ip` as configured on the interface
    pub prefix: Option<u8>,
    /// Point-to-point peer address (net30/p2p topologies only)
    pub peer_ip: Option<Ipv4Addr>,
    /// Public address of the VPN server
    pub remote_ip: Option<Ipv4Addr>,
}

/// Where the current authentication round stands. Decides whether an
/// authentication failure counts towards [`MAX_SSO_FAILURES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Round {
    /// Connecting interactively: placeholder credentials and/or SSO login
    Interactive,
    /// We sent the cached auth-token; rejection is expected once it expires
    CachedToken,
    /// Tunnel is up; a failure is the server rejecting the session token
    Connected,
    /// This round's failure was already handled
    Failed,
}

/// Side effects requested by [`Protocol`]
#[derive(Debug, Clone, PartialEq, Eq)]
enum Action {
    /// Write a command to the management interface
    Send(String),
    /// Report an event to the D-Bus layer
    Emit(VpnEvent),
    /// Open this SSO URL in the user's browser
    OpenBrowser(String),
    /// Remember this server auth-token for the next connection
    CacheToken(String),
    /// Forget the cached auth-token; the server no longer accepts it
    ClearCachedToken,
    /// The tunnel is up
    Connected {
        local_ip: Option<Ipv4Addr>,
        remote_ip: Option<Ipv4Addr>,
    },
    /// Give up: stop OpenVPN and report this failure
    Fail { reason: String, kind: FailureKind },
}

/// Management interface state machine
#[derive(Debug)]
struct Protocol {
    username: String,
    password: String,
    /// Auth-token from an earlier connection, tried once before SSO
    cached_token: Option<String>,
    /// State of the current authentication round
    round: Round,
    /// SSO URL already opened in the current authentication round
    opened_url: Option<String>,
    /// SSO rounds that failed since the tunnel was last up
    sso_failures: u32,
}

impl Protocol {
    fn new(username: &str, password: &str, cached_token: Option<String>) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
            cached_token,
            round: Round::Interactive,
            opened_url: None,
            sso_failures: 0,
        }
    }

    /// Handle one line from the management interface
    fn handle_line(&mut self, line: &str) -> Vec<Action> {
        if line.starts_with(">HOLD:") {
            // OpenVPN holds before the first connection and again before
            // every internal restart. Not releasing it stalls the tunnel.
            return vec![Action::Send("hold release\n".to_string())];
        }
        if let Some(msg) = line.strip_prefix(">PASSWORD:") {
            return self.on_password(msg);
        }
        if let Some(msg) = line.strip_prefix(">STATE:") {
            return self.on_state(msg);
        }
        if let Some(msg) = line
            .strip_prefix(">INFOMSG:")
            .or_else(|| line.strip_prefix(">INFO:"))
        {
            return extract_auth_url(msg)
                .map(|url| self.open_url(url))
                .unwrap_or_default();
        }
        if let Some(msg) = line.strip_prefix(">FATAL:") {
            return vec![Action::Fail {
                reason: format!("OpenVPN fatal error: {msg}"),
                kind: FailureKind::Connect,
            }];
        }
        Vec::new()
    }

    fn on_password(&mut self, msg: &str) -> Vec<Action> {
        if let Some(token) = msg.strip_prefix("Auth-Token:") {
            let token = token.trim();
            if token.is_empty() {
                return Vec::new();
            }
            return vec![Action::CacheToken(token.to_string())];
        }
        if msg.starts_with("Need 'Auth'") {
            return self.on_credentials_needed();
        }
        if msg.starts_with("Verification Failed") {
            return self.on_verification_failed(msg);
        }
        warn!("Unsupported password request from OpenVPN: {msg}");
        Vec::new()
    }

    fn on_credentials_needed(&mut self) -> Vec<Action> {
        // A credential request starts a new authentication round: the next
        // SSO URL must open the browser even if it repeats the previous one.
        self.opened_url = None;

        if self.sso_failures >= MAX_SSO_FAILURES {
            return vec![self.give_up()];
        }

        let (round, password) = match self.cached_token.take() {
            Some(token) => (Round::CachedToken, token),
            None => (Round::Interactive, self.password.clone()),
        };
        self.round = round;

        // The username must be the same for placeholder credentials and
        // cached tokens: OpenVPN auth-tokens are bound to the username.
        vec![
            Action::Send(format!(
                "username \"Auth\" \"{}\"\n",
                escape_management_string(&self.username)
            )),
            Action::Send(format!(
                "password \"Auth\" \"{}\"\n",
                escape_management_string(&password)
            )),
        ]
    }

    fn on_verification_failed(&mut self, msg: &str) -> Vec<Action> {
        // Whatever token we hold is dead: the cached one we just sent, or the
        // session token OpenVPN presented during renegotiation. With
        // --auth-retry interact OpenVPN restarts and asks for credentials
        // again, and the next round goes through SSO.
        let mut actions = vec![Action::ClearCachedToken];
        actions.extend(self.on_auth_failure());
        if let Some(url) = extract_auth_url(msg) {
            actions.extend(self.open_url(url));
        }
        actions
    }

    /// Handle an authentication failure, reported as ">PASSWORD:Verification
    /// Failed" and/or "RECONNECTING,auth-failure". Only a failed interactive
    /// round (SSO timeout, denied login, rejected placeholder) counts; the
    /// round is marked so the second signal for the same failure is ignored.
    fn on_auth_failure(&mut self) -> Vec<Action> {
        let round = std::mem::replace(&mut self.round, Round::Failed);
        if round != Round::Interactive {
            return Vec::new();
        }
        self.sso_failures += 1;
        if self.sso_failures >= MAX_SSO_FAILURES {
            return vec![self.give_up()];
        }
        Vec::new()
    }

    fn give_up(&self) -> Action {
        Action::Fail {
            reason: format!(
                "SSO authentication failed {} times in a row",
                self.sso_failures
            ),
            kind: FailureKind::Login,
        }
    }

    fn on_state(&mut self, msg: &str) -> Vec<Action> {
        // time,name,description,local_ip,remote_ip,remote_port,local_addr,local_port,local_ipv6
        let fields: Vec<&str> = msg.split(',').collect();
        let field = |i: usize| fields.get(i).copied().filter(|s| !s.is_empty());

        let state = match field(1).unwrap_or_default() {
            "CONNECTING" | "WAIT" | "RESOLVE" | "TCP_CONNECT" => {
                // A new connection attempt starts a new round. Without
                // credentials there is no password request to mark it.
                if self.round == Round::Failed {
                    self.round = Round::Interactive;
                }
                VpnState::Connecting
            }
            "AUTH" => VpnState::Authenticating,
            "AUTH_PENDING" => {
                let mut actions = extract_open_url(msg)
                    .map(|url| self.open_url(url))
                    .unwrap_or_default();
                actions.push(Action::Emit(VpnEvent::State(VpnState::Authenticating)));
                return actions;
            }
            "GET_CONFIG" | "ASSIGN_IP" | "ADD_ROUTES" => VpnState::GettingConfig,
            "CONNECTED" => {
                self.sso_failures = 0;
                self.round = Round::Connected;
                self.opened_url = None;
                return vec![Action::Connected {
                    local_ip: field(3).and_then(|s| s.parse().ok()),
                    remote_ip: field(4).and_then(|s| s.parse().ok()),
                }];
            }
            "RECONNECTING" => {
                let mut actions = if field(2).is_some_and(|d| d.starts_with("auth-failure")) {
                    self.on_auth_failure()
                } else {
                    Vec::new()
                };
                actions.push(Action::Emit(VpnEvent::State(VpnState::Reconnecting)));
                return actions;
            }
            "EXITING" => VpnState::Stopping,
            _ => return Vec::new(),
        };
        vec![Action::Emit(VpnEvent::State(state))]
    }

    /// Open `url` unless it was already opened in this authentication round
    /// (servers often announce the same URL via AUTH_PENDING and INFOMSG).
    fn open_url(&mut self, url: String) -> Vec<Action> {
        if self.opened_url.as_deref() == Some(url.as_str()) {
            return Vec::new();
        }
        self.opened_url = Some(url.clone());
        self.round = Round::Interactive;
        vec![Action::OpenBrowser(url)]
    }
}

/// OpenVPN process manager
pub struct OpenVpnManager {
    config: ConnectionConfig,
    socket_path: PathBuf,
    process: Option<Child>,
    event_tx: mpsc::Sender<VpnEvent>,
    /// Sanitized copy of the .ovpn file (only if we had to create one)
    temp_config_path: Option<PathBuf>,
    /// Triggered by the D-Bus layer to end the connection
    stop: Arc<Notify>,
    /// Running browser / OAuth callback flow
    sso_task: Option<JoinHandle<()>>,
    /// Failure decided by the protocol, reported once OpenVPN has exited
    failure: Option<(String, FailureKind)>,
}

impl OpenVpnManager {
    pub fn new(config: ConnectionConfig, event_tx: mpsc::Sender<VpnEvent>) -> Self {
        let socket_path =
            PathBuf::from(RUNTIME_DIR).join(format!("nm-openvpn-sso-{}.sock", config.uuid));

        Self {
            config,
            socket_path,
            process: None,
            event_tx,
            temp_config_path: None,
            stop: Arc::new(Notify::new()),
            sso_task: None,
            failure: None,
        }
    }

    /// Handle used to stop [`run`](Self::run) from another task
    pub fn stop_handle(&self) -> Arc<Notify> {
        self.stop.clone()
    }

    /// Run the connection until it is stopped or fails for good. Always ends
    /// by reporting `Stopped`, preceded by `Failed` unless stopped on request.
    pub async fn run(mut self) {
        let result = self.supervise().await;
        self.shutdown().await;

        if let Err(e) = result {
            let (reason, kind) = self
                .failure
                .take()
                .unwrap_or_else(|| (format!("{e:#}"), FailureKind::Connect));
            error!("VPN connection failed: {reason}");
            self.emit(VpnEvent::Failed { reason, kind }).await;
        }
        self.emit(VpnEvent::State(VpnState::Stopped)).await;
    }

    /// Start OpenVPN and drive the management interface. Returns Ok(()) when
    /// stopped on request and Err(_) when the connection ended on its own.
    async fn supervise(&mut self) -> Result<()> {
        let (mut reader, mut writer) = match self.start_openvpn().await {
            Ok(rw) => rw,
            Err(e) => {
                if let Some(child) = self.process.as_mut() {
                    let _ = child.start_kill();
                }
                return Err(e);
            }
        };

        // A cached token can only be offered when OpenVPN asks for credentials
        let cached_token = if self.config.uses_credentials() {
            secrets::get_cached_credentials(&self.config.uuid)
                .await
                .filter(|tokens| tokens.is_valid())
                .map(|tokens| tokens.access_token)
        } else {
            None
        };
        if cached_token.is_some() {
            info!("Found cached auth-token, trying it before SSO");
        }
        let mut protocol = Protocol::new(
            self.config.auth_username(),
            self.config.auth_password(),
            cached_token,
        );

        writer
            .write_all(b"state on\nhold release\n")
            .await
            .context("Failed to write to management interface")?;

        let stop = self.stop.clone();
        let mut buf = Vec::new();
        loop {
            buf.clear();
            tokio::select! {
                biased;
                _ = stop.notified() => {
                    info!("Stop requested, terminating OpenVPN");
                    self.emit(VpnEvent::State(VpnState::Stopping)).await;
                    let _ = writer.write_all(b"signal SIGTERM\n").await;
                    return Ok(());
                }
                read = reader.read_until(b'\n', &mut buf) => {
                    if read.context("Failed to read from management interface")? == 0 {
                        return Err(anyhow!(
                            "OpenVPN exited unexpectedly (management interface closed)"
                        ));
                    }
                }
            }

            let line = String::from_utf8_lossy(&buf);
            let line = line.trim_end();
            if !line.starts_with(">BYTECOUNT") {
                info!("MGMT: {}", redact_secrets(line));
            }
            for action in protocol.handle_line(line) {
                self.apply(action, &mut writer).await?;
            }
        }
    }

    async fn apply(&mut self, action: Action, writer: &mut OwnedWriteHalf) -> Result<()> {
        match action {
            Action::Send(command) => writer
                .write_all(command.as_bytes())
                .await
                .context("Failed to write to management interface")?,
            Action::Emit(event) => self.emit(event).await,
            Action::OpenBrowser(url) => self.start_browser_auth(url),
            Action::CacheToken(token) => cache_token(&self.config.uuid, token).await,
            Action::ClearCachedToken => secrets::clear_cached_credentials(&self.config.uuid).await,
            Action::Connected {
                local_ip,
                remote_ip,
            } => {
                let config = describe_tunnel(local_ip, remote_ip).await;
                info!("VPN connected: {config:?}");
                self.emit(VpnEvent::Connected(config)).await;
            }
            Action::Fail { reason, kind } => {
                warn!("Giving up: {reason}");
                self.failure = Some((reason, kind));
                let _ = writer.write_all(b"signal SIGTERM\n").await;
            }
        }
        Ok(())
    }

    async fn emit(&self, event: VpnEvent) {
        if self.event_tx.send(event).await.is_err() {
            warn!("D-Bus event channel closed");
        }
    }

    /// Open the SSO URL in the background so the management loop keeps
    /// running (and can still be stopped) while the user logs in.
    fn start_browser_auth(&mut self, url: String) {
        if let Some(previous) = self.sso_task.take() {
            previous.abort();
        }
        info!("Starting SSO authentication in the browser");
        self.sso_task = Some(tokio::spawn(async move {
            let result = match oauth::localhost_callback_base(&url) {
                Some(server_base) => oauth::authenticate_sso(&url, &server_base).await,
                None => oauth::authenticate(&url).await,
            };
            if let Err(e) = result {
                error!("SSO authentication failed: {e:#}");
            }
        }));
    }

    /// Start OpenVPN and connect to its management socket
    async fn start_openvpn(&mut self) -> Result<(BufReader<OwnedReadHalf>, OwnedWriteHalf)> {
        kill_stale_openvpn_processes(&self.socket_path).await;
        ensure_runtime_dir().await;
        let _ = tokio::fs::remove_file(&self.socket_path).await;

        let config_file = match self.config.config_path.clone() {
            Some(path) => Some(self.prepare_config_file(path).await?),
            None => None,
        };
        let socket = self
            .socket_path
            .to_str()
            .ok_or_else(|| anyhow!("Management socket path is not valid UTF-8"))?;
        let args = self.config.build_openvpn_args(socket, config_file.as_ref());

        info!("Starting OpenVPN with args: {:?}", args);

        let mut child = Command::new("openvpn")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("Failed to start OpenVPN process")?;

        // OpenVPN logs to stdout. An undrained pipe fills up after a day or
        // so of renegotiations and then blocks OpenVPN completely.
        if let Some(stdout) = child.stdout.take() {
            forward_output(stdout);
        }
        if let Some(stderr) = child.stderr.take() {
            forward_output(stderr);
        }

        info!("OpenVPN started with PID {:?}", child.id());
        self.process = Some(child);
        self.wait_for_socket().await?;

        let stream = UnixStream::connect(&self.socket_path)
            .await
            .context("Failed to connect to management socket")?;
        let (reader, writer) = stream.into_split();
        Ok((BufReader::new(reader), writer))
    }

    /// Decide how OpenVPN reads the .ovpn file (see [`ovpn`]) and write
    /// the private copy if one is needed. The copy lives in the runtime
    /// directory: SELinux lets OpenVPN read files there, but not files
    /// NetworkManager creates in /tmp.
    async fn prepare_config_file(&mut self, path: PathBuf) -> Result<ConfigFile> {
        let prepared = tokio::task::spawn_blocking(move || ovpn::prepare(&path))
            .await
            .context("Config file check panicked")??;
        match prepared {
            Prepared::InPlace { path, dir } => Ok(ConfigFile {
                path,
                dir: Some(dir),
                untrusted: false,
            }),
            Prepared::Copy {
                text,
                dir,
                untrusted,
            } => {
                let copy = PathBuf::from(RUNTIME_DIR)
                    .join(format!("nm-openvpn-sso-{}.ovpn", self.config.uuid));
                write_private_file(&copy, text.as_bytes())
                    .with_context(|| format!("Failed to write {}", copy.display()))?;
                self.temp_config_path = Some(copy.clone());
                Ok(ConfigFile {
                    path: copy,
                    dir,
                    untrusted,
                })
            }
        }
    }

    /// Wait for the management socket to appear
    async fn wait_for_socket(&mut self) -> Result<()> {
        for _ in 0..50 {
            if self.socket_path.exists() {
                return Ok(());
            }
            if let Some(child) = self.process.as_mut() {
                if let Some(status) = child.try_wait()? {
                    return Err(anyhow!(
                        "OpenVPN exited with {status} before creating the management socket \
                         (its output is logged above)"
                    ));
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err(anyhow!("Management socket not created after 5s"))
    }

    /// Wait for OpenVPN to exit (killing it if needed) and clean up
    async fn shutdown(&mut self) {
        if let Some(task) = self.sso_task.take() {
            task.abort();
        }
        if let Some(mut child) = self.process.take() {
            match tokio::time::timeout(OPENVPN_EXIT_TIMEOUT, child.wait()).await {
                Ok(Ok(status)) => info!("OpenVPN exited: {status}"),
                Ok(Err(e)) => warn!("Failed to wait for OpenVPN: {e}"),
                Err(_) => {
                    warn!("OpenVPN did not exit within {OPENVPN_EXIT_TIMEOUT:?}, killing it");
                    let _ = child.kill().await;
                }
            }
        }
        self.remove_runtime_files();
    }

    fn remove_runtime_files(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
        if let Some(temp_config) = self.temp_config_path.take() {
            let _ = std::fs::remove_file(temp_config);
        }
    }
}

impl Drop for OpenVpnManager {
    fn drop(&mut self) {
        // Reached without shutdown() only when the task is aborted. The child
        // was spawned with kill_on_drop, so dropping it kills OpenVPN.
        if let Some(task) = self.sso_task.take() {
            task.abort();
        }
        self.remove_runtime_files();
    }
}

/// Log every line of an OpenVPN output stream until it closes
fn forward_output(stream: impl AsyncRead + Unpin + Send + 'static) {
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf).await {
                Ok(0) => break,
                Ok(_) => {
                    let line = String::from_utf8_lossy(&buf);
                    info!(target: "openvpn", "openvpn: {}", redact_secrets(line.trim_end()));
                }
                Err(e) => {
                    warn!("Failed to read OpenVPN output: {e}");
                    break;
                }
            }
        }
    });
}

/// Kill openvpn processes left over from an earlier run on our socket
async fn kill_stale_openvpn_processes(socket_path: &Path) {
    let pattern = format!("openvpn.*{}", socket_path.display());
    if let Ok(output) = Command::new("pkill").args(["-f", &pattern]).output().await {
        if output.status.success() {
            info!(
                "Killed stale openvpn processes using {}",
                socket_path.display()
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

async fn ensure_runtime_dir() {
    let dir = Path::new(RUNTIME_DIR);
    if dir.exists() {
        return;
    }
    info!("Creating runtime directory: {RUNTIME_DIR}");
    match tokio::fs::create_dir_all(dir).await {
        Ok(()) => {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
        }
        Err(e) => warn!("Failed to create runtime directory {RUNTIME_DIR}: {e}"),
    }
}

/// Write a root-only file without following a pre-planted symlink
fn write_private_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let _ = std::fs::remove_file(path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)
}

async fn cache_token(connection_uuid: &str, token: String) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let tokens = secrets::StoredTokens {
        access_token: token,
        refresh_token: None,
        expires_at: Some(now + CACHED_TOKEN_TTL_SECS),
    };
    if let Err(e) = secrets::cache_credentials(connection_uuid, tokens).await {
        warn!("Failed to cache auth-token: {e:#}");
    }
}

/// Build the tunnel description for NetworkManager. OpenVPN has already
/// configured the interface, so the kernel is the source of truth for the
/// device name and prefix length.
async fn describe_tunnel(local_ip: Option<Ipv4Addr>, remote_ip: Option<Ipv4Addr>) -> VpnConfig {
    let mut config = VpnConfig {
        local_ip,
        remote_ip,
        ..Default::default()
    };
    let Some(ip) = local_ip else {
        return config;
    };

    match Command::new("ip")
        .args(["-j", "-4", "addr", "show"])
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            match find_interface_with_address(&output.stdout, ip) {
                Some(iface) => {
                    config.tun_device = Some(iface.name);
                    config.prefix = Some(iface.prefix);
                    config.peer_ip = iface.peer;
                }
                None => warn!("No network interface carries the tunnel address {ip}"),
            }
        }
        Ok(output) => warn!("`ip addr` failed with {}", output.status),
        Err(e) => warn!("Failed to run `ip addr`: {e}"),
    }
    config
}

#[derive(Debug, PartialEq, Eq)]
struct TunnelInterface {
    name: String,
    prefix: u8,
    peer: Option<Ipv4Addr>,
}

/// Find the interface holding `ip` in `ip -j -4 addr show` output
fn find_interface_with_address(json: &[u8], ip: Ipv4Addr) -> Option<TunnelInterface> {
    #[derive(Deserialize)]
    struct Link {
        ifname: String,
        #[serde(default)]
        addr_info: Vec<AddrInfo>,
    }
    #[derive(Deserialize)]
    struct AddrInfo {
        local: Option<String>,
        prefixlen: Option<u8>,
        /// Peer address on point-to-point links
        address: Option<String>,
    }

    let links: Vec<Link> = serde_json::from_slice(json).ok()?;
    links.into_iter().find_map(|link| {
        let addr = link
            .addr_info
            .iter()
            .find(|a| a.local.as_deref().and_then(|s| s.parse().ok()) == Some(ip))?;
        Some(TunnelInterface {
            prefix: addr.prefixlen.unwrap_or(32),
            peer: addr.address.as_deref().and_then(|s| s.parse().ok()),
            name: link.ifname,
        })
    })
}

/// Extract OPEN_URL from an OpenVPN message, e.g. the AUTH_PENDING state
/// details "timeout 120,OPEN_URL:http://host:port/path?query"
fn extract_open_url(message: &str) -> Option<String> {
    let start = message.find("OPEN_URL:")? + "OPEN_URL:".len();
    let rest = &message[start..];
    let end = rest
        .find(|c: char| c == ',' || c.is_whitespace())
        .unwrap_or(rest.len());
    let url = &rest[..end];
    (!url.is_empty()).then(|| url.to_string())
}

/// Extract an SSO URL from an OpenVPN message
fn extract_auth_url(message: &str) -> Option<String> {
    // WEB_AUTH:flags:url (e.g. WEB_AUTH::https://... or WEB_AUTH:hidden:https://...)
    if let Some(start) = message.find("WEB_AUTH:") {
        let after = &message[start + "WEB_AUTH:".len()..];
        if let Some(url_start) = after.find("http://").or_else(|| after.find("https://")) {
            let url = &after[url_start..];
            let end = url.find(char::is_whitespace).unwrap_or(url.len());
            return Some(url[..end].to_string());
        }
    }

    // OPEN_URL:http://... (AUTH_PENDING state or control message)
    if let Some(url) = extract_open_url(message) {
        return Some(url);
    }

    // Fallback: any http(s) URL in the message (also covers CRV1 challenge text)
    message
        .split_whitespace()
        .find(|word| word.starts_with("http://") || word.starts_with("https://"))
        .map(|word| word.trim_matches(|c| c == '"' || c == '\'').to_string())
}

/// Hide auth-token values before a line is logged. Matches both the
/// management notification (">PASSWORD:Auth-Token:<token>") and pushed
/// options ("auth-token <token>", "auth-token-user <user>").
fn redact_secrets(line: &str) -> String {
    const MARKER: &str = "auth-token";
    // ASCII lowercasing keeps byte offsets identical to `line`
    let lower = line.to_ascii_lowercase();
    let mut out = String::with_capacity(line.len());
    let mut pos = 0;

    while let Some(found) = lower[pos..].find(MARKER) {
        let after_marker = pos + found + MARKER.len();
        // Optional suffix such as "-user"
        let suffix_len = line[after_marker..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .unwrap_or(line.len() - after_marker);
        let after_suffix = after_marker + suffix_len;
        let sep_len = line[after_suffix..]
            .find(|c: char| !matches!(c, ':' | ' ' | '='))
            .unwrap_or(line.len() - after_suffix);
        if sep_len == 0 {
            // Mentions the option without a value, e.g. "(auth-token)"
            out.push_str(&line[pos..after_suffix]);
            pos = after_suffix;
            continue;
        }
        let value_start = after_suffix + sep_len;
        let value_len = line[value_start..]
            .find(|c: char| c == ',' || c == '\'' || c == '"' || c.is_whitespace())
            .unwrap_or(line.len() - value_start);
        out.push_str(&line[pos..value_start]);
        if value_len > 0 {
            out.push_str("<redacted>");
        }
        pos = value_start + value_len;
    }
    out.push_str(&line[pos..]);
    out
}

/// Escape a value for a double-quoted management interface argument
fn escape_management_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\n', '\r'], "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send(cmd: &str) -> Action {
        Action::Send(cmd.to_string())
    }

    fn state(s: VpnState) -> Action {
        Action::Emit(VpnEvent::State(s))
    }

    fn placeholder_credentials() -> Vec<Action> {
        vec![
            send("username \"Auth\" \"oauth\"\n"),
            send("password \"Auth\" \"oauth\"\n"),
        ]
    }

    /// Feed lines and collect every action they produce
    fn feed(protocol: &mut Protocol, lines: &[&str]) -> Vec<Action> {
        lines
            .iter()
            .flat_map(|line| protocol.handle_line(line))
            .collect()
    }

    /// Replays a journal transcript of the reported bug: about 55 minutes
    /// after connecting, renegotiation fails because the server rejects the
    /// auth-token. OpenVPN restarts and waits in a management hold; the old
    /// code never released it and refused to re-open the browser.
    #[test]
    fn reauthenticates_after_auth_token_is_rejected() {
        let mut p = Protocol::new("oauth", "oauth", None);

        assert_eq!(
            feed(
                &mut p,
                &[">INFO:OpenVPN Management Interface Version 6 -- type 'help' for more info"]
            ),
            vec![]
        );
        assert_eq!(
            feed(&mut p, &[">HOLD:Waiting for hold release:0"]),
            vec![send("hold release\n")]
        );
        assert_eq!(
            feed(
                &mut p,
                &[
                    "SUCCESS: real-time state notification set to ON",
                    "SUCCESS: hold release succeeded",
                    ">PASSWORD:Need 'Auth' username/password",
                ]
            ),
            placeholder_credentials()
        );
        assert_eq!(
            feed(
                &mut p,
                &[
                    "SUCCESS: 'Auth' username entered, but not yet verified",
                    ">STATE:1794299884,RESOLVE,,,,,,",
                    ">STATE:1794299884,AUTH,,,,,,",
                    ">STATE:1794299885,AUTH_PENDING,timeout 180,,,,,",
                    ">INFOMSG:WEB_AUTH::https://vpn.example.com:9000/oauth2/start?state=first",
                ]
            ),
            vec![
                state(VpnState::Connecting),
                state(VpnState::Authenticating),
                state(VpnState::Authenticating),
                Action::OpenBrowser("https://vpn.example.com:9000/oauth2/start?state=first".into()),
            ]
        );
        assert_eq!(
            feed(
                &mut p,
                &[
                    ">STATE:1794299886,GET_CONFIG,,,,,,",
                    ">PASSWORD:Auth-Token:SESS_ID_AT_token1",
                    ">STATE:1794299887,CONNECTED,SUCCESS,10.8.0.5,52.19.23.151,1194,,,fe80::1",
                ]
            ),
            vec![
                state(VpnState::GettingConfig),
                Action::CacheToken("SESS_ID_AT_token1".into()),
                Action::Connected {
                    local_ip: Some(Ipv4Addr::new(10, 8, 0, 5)),
                    remote_ip: Some(Ipv4Addr::new(52, 19, 23, 151)),
                },
            ]
        );

        // ~55 minutes later: renegotiation with the auth-token fails
        assert_eq!(
            feed(
                &mut p,
                &[
                    ">PASSWORD:Verification Failed: 'Auth'",
                    ">STATE:1794303150,RECONNECTING,auth-failure (auth-token),,,,,",
                ]
            ),
            vec![Action::ClearCachedToken, state(VpnState::Reconnecting)]
        );
        assert_eq!(
            feed(&mut p, &[">HOLD:Waiting for hold release:2"]),
            vec![send("hold release\n")]
        );
        assert_eq!(
            feed(&mut p, &[">PASSWORD:Need 'Auth' username/password"]),
            placeholder_credentials()
        );
        assert_eq!(
            feed(
                &mut p,
                &[
                    ">STATE:1794303151,AUTH_PENDING,timeout 180,,,,,",
                    ">INFOMSG:WEB_AUTH::https://vpn.example.com:9000/oauth2/start?state=second",
                    ">STATE:1794303160,CONNECTED,SUCCESS,10.8.0.6,52.19.23.151,1194,,,",
                ]
            ),
            vec![
                state(VpnState::Authenticating),
                Action::OpenBrowser(
                    "https://vpn.example.com:9000/oauth2/start?state=second".into()
                ),
                Action::Connected {
                    local_ip: Some(Ipv4Addr::new(10, 8, 0, 6)),
                    remote_ip: Some(Ipv4Addr::new(52, 19, 23, 151)),
                },
            ]
        );
        // Token rejection during renegotiation is not counted as an SSO failure
        assert_eq!(p.sso_failures, 0);
    }

    #[test]
    fn falls_back_to_sso_when_cached_token_is_rejected() {
        let mut p = Protocol::new("oauth", "oauth", Some("SESS_ID_AT_old".into()));

        assert_eq!(
            feed(&mut p, &[">PASSWORD:Need 'Auth' username/password"]),
            vec![
                send("username \"Auth\" \"oauth\"\n"),
                send("password \"Auth\" \"SESS_ID_AT_old\"\n"),
            ]
        );
        assert_eq!(
            feed(
                &mut p,
                &[
                    ">PASSWORD:Verification Failed: 'Auth'",
                    ">STATE:1,RECONNECTING,auth-failure,,,,,",
                    ">HOLD:Waiting for hold release:2",
                    ">PASSWORD:Need 'Auth' username/password",
                ]
            ),
            [
                vec![
                    Action::ClearCachedToken,
                    state(VpnState::Reconnecting),
                    send("hold release\n"),
                ],
                placeholder_credentials(),
            ]
            .concat()
        );
        assert_eq!(p.sso_failures, 0);
    }

    fn give_up() -> Action {
        Action::Fail {
            reason: format!("SSO authentication failed {MAX_SSO_FAILURES} times in a row"),
            kind: FailureKind::Login,
        }
    }

    #[test]
    fn gives_up_after_repeated_sso_failures() {
        let mut p = Protocol::new("oauth", "oauth", None);
        for round in 1..MAX_SSO_FAILURES {
            assert_eq!(
                feed(&mut p, &[">PASSWORD:Need 'Auth' username/password"]),
                placeholder_credentials(),
                "round {round}"
            );
            assert_eq!(
                feed(
                    &mut p,
                    &[
                        ">PASSWORD:Verification Failed: 'Auth'",
                        ">STATE:1,RECONNECTING,auth-failure,,,,,",
                    ]
                ),
                vec![Action::ClearCachedToken, state(VpnState::Reconnecting)],
                "round {round}"
            );
            // Both failure signals together count once
            assert_eq!(p.sso_failures, round);
        }
        feed(&mut p, &[">PASSWORD:Need 'Auth' username/password"]);
        assert_eq!(
            feed(&mut p, &[">PASSWORD:Verification Failed: 'Auth'"]),
            vec![Action::ClearCachedToken, give_up()]
        );
        // Any further credential request is refused too
        assert_eq!(
            feed(&mut p, &[">PASSWORD:Need 'Auth' username/password"]),
            vec![give_up()]
        );
    }

    /// Without credentials (stock-client behavior) OpenVPN never asks for a
    /// password: the SSO URL arrives directly, and failures are recognized
    /// from the browser login that did not complete.
    #[test]
    fn sso_without_credentials_connects_and_counts_failures() {
        let mut p = Protocol::new("oauth", "oauth", None);
        let failed_round = |p: &mut Protocol, n: u32| {
            feed(
                p,
                &[
                    ">HOLD:Waiting for hold release:0",
                    ">STATE:1,RESOLVE,,,,,,",
                    ">STATE:1,AUTH,,,,,,",
                    ">STATE:1,AUTH_PENDING,timeout 180,,,,,",
                    &format!(">INFOMSG:WEB_AUTH::https://vpn.example.com/oauth2/start?state={n}"),
                    ">PASSWORD:Verification Failed: 'Auth'",
                    ">STATE:1,RECONNECTING,auth-failure,,,,,",
                ],
            )
        };

        let first = failed_round(&mut p, 1);
        assert!(first.contains(&send("hold release\n")));
        assert!(first.contains(&Action::OpenBrowser(
            "https://vpn.example.com/oauth2/start?state=1".into()
        )));
        assert!(!first
            .iter()
            .any(|a| matches!(a, Action::Send(c) if c.starts_with("username"))));
        assert_eq!(p.sso_failures, 1);

        assert!(!failed_round(&mut p, 2).contains(&give_up()));
        assert!(failed_round(&mut p, 3).contains(&give_up()));
    }

    #[test]
    fn rejected_session_token_without_credentials_reopens_browser() {
        let mut p = Protocol::new("oauth", "oauth", None);
        feed(
            &mut p,
            &[
                ">STATE:1,AUTH_PENDING,timeout 180,,,,,",
                ">INFOMSG:WEB_AUTH::https://vpn.example.com/oauth2/start?state=a",
                ">STATE:2,CONNECTED,SUCCESS,10.8.0.5,52.19.23.151,1194,,,",
            ],
        );
        assert_eq!(
            feed(
                &mut p,
                &[
                    ">PASSWORD:Verification Failed: 'Auth'",
                    ">STATE:3,RECONNECTING,auth-failure (auth-token),,,,,",
                    ">HOLD:Waiting for hold release:2",
                    ">STATE:4,RESOLVE,,,,,,",
                    ">INFOMSG:WEB_AUTH::https://vpn.example.com/oauth2/start?state=b",
                ]
            ),
            vec![
                Action::ClearCachedToken,
                state(VpnState::Reconnecting),
                send("hold release\n"),
                state(VpnState::Connecting),
                Action::OpenBrowser("https://vpn.example.com/oauth2/start?state=b".into()),
            ]
        );
        // The rejected session token is expected, not an SSO failure
        assert_eq!(p.sso_failures, 0);
    }

    #[test]
    fn immediate_rejections_without_browser_still_give_up() {
        // Guards against a tight reconnect loop when the server rejects us
        // before any SSO login (hold release skips OpenVPN's retry pause)
        let mut p = Protocol::new("oauth", "oauth", None);
        let mut actions = Vec::new();
        for _ in 0..MAX_SSO_FAILURES {
            actions = feed(
                &mut p,
                &[
                    ">STATE:1,RESOLVE,,,,,,",
                    ">STATE:1,RECONNECTING,auth-failure,,,,,",
                ],
            );
        }
        assert!(actions.contains(&give_up()));
    }

    #[test]
    fn successful_connection_resets_sso_failure_count() {
        let mut p = Protocol::new("oauth", "oauth", None);
        feed(
            &mut p,
            &[
                ">PASSWORD:Need 'Auth' username/password",
                ">PASSWORD:Verification Failed: 'Auth'",
                ">PASSWORD:Need 'Auth' username/password",
                ">STATE:1,CONNECTED,SUCCESS,10.8.0.5,1.2.3.4,1194,,,",
            ],
        );
        assert_eq!(p.sso_failures, 0);
    }

    #[test]
    fn opens_each_sso_url_once_per_round() {
        let mut p = Protocol::new("oauth", "oauth", None);
        feed(&mut p, &[">PASSWORD:Need 'Auth' username/password"]);
        assert_eq!(
            feed(
                &mut p,
                &[
                    ">STATE:1,AUTH_PENDING,timeout 120,OPEN_URL:https://sso.example.com/start?x=1,,,",
                    ">INFOMSG:OPEN_URL:https://sso.example.com/start?x=1",
                ]
            ),
            vec![
                Action::OpenBrowser("https://sso.example.com/start?x=1".into()),
                state(VpnState::Authenticating),
            ]
        );

        // A new credential request starts a new round: same URL opens again
        feed(&mut p, &[">PASSWORD:Need 'Auth' username/password"]);
        assert_eq!(
            feed(
                &mut p,
                &[">INFOMSG:OPEN_URL:https://sso.example.com/start?x=1"]
            ),
            vec![Action::OpenBrowser(
                "https://sso.example.com/start?x=1".into()
            )]
        );
    }

    #[test]
    fn fatal_error_fails_the_connection() {
        let mut p = Protocol::new("oauth", "oauth", None);
        assert_eq!(
            feed(&mut p, &[">FATAL:Cannot open TUN/TAP dev"]),
            vec![Action::Fail {
                reason: "OpenVPN fatal error: Cannot open TUN/TAP dev".into(),
                kind: FailureKind::Connect,
            }]
        );
    }

    #[test]
    fn escapes_credentials() {
        let mut p = Protocol::new("us\"er", "pa\\ss\nword", None);
        assert_eq!(
            feed(&mut p, &[">PASSWORD:Need 'Auth' username/password"]),
            vec![
                send("username \"Auth\" \"us\\\"er\"\n"),
                send("password \"Auth\" \"pa\\\\ssword\"\n"),
            ]
        );
    }

    #[test]
    fn extracts_auth_urls() {
        assert_eq!(
            extract_auth_url("WEB_AUTH::https://vpn.example.com:9000/oauth2/start?state=abc"),
            Some("https://vpn.example.com:9000/oauth2/start?state=abc".into())
        );
        assert_eq!(
            extract_auth_url("WEB_AUTH:hidden:https://sso.example.com/a b"),
            Some("https://sso.example.com/a".into())
        );
        assert_eq!(
            extract_auth_url("timeout 120,OPEN_URL:http://10.0.0.1:9000/start?a=1,x"),
            Some("http://10.0.0.1:9000/start?a=1".into())
        );
        assert_eq!(
            extract_auth_url("OpenVPN Management Interface Version 6 -- type 'help'"),
            None
        );
    }

    #[test]
    fn redacts_auth_tokens() {
        assert_eq!(
            redact_secrets(">PASSWORD:Auth-Token:SESS_ID_AT_abc/def=="),
            ">PASSWORD:Auth-Token:<redacted>"
        );
        assert_eq!(
            redact_secrets("PUSH_REPLY,route-gateway 10.8.0.1,auth-token SESS_ID_AT_x,peer-id 0"),
            "PUSH_REPLY,route-gateway 10.8.0.1,auth-token <redacted>,peer-id 0"
        );
        assert_eq!(
            redact_secrets("auth-token-user dXNlcg==,ping 10"),
            "auth-token-user <redacted>,ping 10"
        );
        assert_eq!(
            redact_secrets(">STATE:1,RECONNECTING,auth-failure (auth-token),,,,,"),
            ">STATE:1,RECONNECTING,auth-failure (auth-token),,,,,"
        );
        assert_eq!(redact_secrets("nothing to see"), "nothing to see");
    }

    #[test]
    fn finds_tunnel_interface_in_ip_json() {
        let json = br#"[
            {"ifindex":1,"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},
            {"ifindex":2,"ifname":"wlo1","addr_info":[]},
            {"ifindex":3,"ifname":"eth0","addr_info":[{},{}]},
            {"ifindex":4,"ifname":"tun0","addr_info":[
                {"family":"inet","local":"10.8.0.8","prefixlen":24,"broadcast":"10.8.0.255"},
                {"family":"inet","local":"8.0.8.10","prefixlen":24}
            ]},
            {"ifindex":5,"ifname":"tun1","addr_info":[
                {"family":"inet","local":"10.9.0.6","address":"10.9.0.5","prefixlen":32}
            ]}
        ]"#;
        assert_eq!(
            find_interface_with_address(json, Ipv4Addr::new(10, 8, 0, 8)),
            Some(TunnelInterface {
                name: "tun0".into(),
                prefix: 24,
                peer: None
            })
        );
        assert_eq!(
            find_interface_with_address(json, Ipv4Addr::new(10, 9, 0, 6)),
            Some(TunnelInterface {
                name: "tun1".into(),
                prefix: 32,
                peer: Some(Ipv4Addr::new(10, 9, 0, 5))
            })
        );
        assert_eq!(
            find_interface_with_address(json, Ipv4Addr::new(10, 1, 1, 1)),
            None
        );
    }
}
