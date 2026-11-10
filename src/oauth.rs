// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

//! OAuth 2.0 browser-based authentication flow

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use notify_rust::Notification;
use serde::Deserialize;
use std::os::unix::fs::{chown, PermissionsExt};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};
use url::Url;

/// Perform OAuth authentication via browser
///
/// For OpenVPN web-auth, the server handles the OAuth callback itself.
/// We just need to open the browser and return immediately - the server
/// will signal auth success through the management interface.
pub async fn authenticate(auth_url: &str) -> Result<()> {
    Url::parse(auth_url).context("Invalid auth URL")?;

    info!("Opening browser for server-handled OAuth authentication");

    let url_owned = auth_url.to_string();
    let browser_opened = tokio::task::spawn_blocking(move || try_open_browser(&url_owned))
        .await
        .unwrap_or(false);

    if browser_opened {
        info!("Browser opened successfully");
        show_notification(
            "VPN Authentication",
            "Please complete login in your browser...",
        );
    } else {
        warn!("Could not open browser automatically");
        show_notification(
            "VPN SSO Login Required",
            &format!("Please open: {}", auth_url),
        );
    }

    info!("SSO Login URL: {}", auth_url);

    Ok(())
}

/// If the SSO URL uses the localhost-callback flow (its `redirect_uri`
/// points at this machine), return the VPN server's base URL, where the
/// authorization code is forwarded. Returns None for native OpenVPN webauth,
/// where the server completes authentication by itself.
pub fn localhost_callback_base(auth_url: &str) -> Option<String> {
    let url = Url::parse(auth_url).ok()?;
    // query_pairs() percent-decodes, so encoded redirect URIs are recognized
    let redirect = url
        .query_pairs()
        .find(|(key, _)| key == "redirect_uri")
        .and_then(|(_, value)| Url::parse(&value).ok())?;
    let is_loopback = match redirect.host()? {
        url::Host::Domain(domain) => domain == "localhost",
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    };
    is_loopback.then(|| url.origin().ascii_serialization())
}

/// Aborts a background task when dropped, on every exit path
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The localhost port for receiving the OAuth callback from Google.
/// This must match CLIENT_OAUTH_CALLBACK_PORT on the server side.
const LOCAL_OAUTH_CALLBACK_PORT: u16 = 19823;

/// Perform SSO authentication with a localhost callback server.
///
/// Flow:
/// 1. Start localhost HTTP server on LOCAL_OAUTH_CALLBACK_PORT
/// 2. Open browser to auth_url (VPN server's /auth/start, which redirects to Google)
/// 3. Google authenticates user, redirects to localhost:LOCAL_OAUTH_CALLBACK_PORT/oauth/callback
/// 4. We receive code + state, POST them to VPN server's /auth/complete
/// 5. VPN server exchanges code, verifies user, sends PUSH_REPLY through VPN tunnel
pub async fn authenticate_sso(auth_url: &str, server_base_url: &str) -> Result<()> {
    info!("Starting SSO authentication flow");
    info!("  Auth URL: {}", auth_url);
    info!("  Server base: {}", server_base_url);

    // Create channel for receiving the OAuth callback result
    let (callback_tx, callback_rx) = oneshot::channel::<Result<(String, String)>>();
    let callback_tx = Arc::new(tokio::sync::Mutex::new(Some(callback_tx)));

    // Start localhost callback server. A previous attempt that was just
    // aborted may not have released the port yet, so retry briefly.
    let mut attempts = 0;
    let listener = loop {
        match TcpListener::bind(("127.0.0.1", LOCAL_OAUTH_CALLBACK_PORT)).await {
            Ok(listener) => break listener,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse && attempts < 10 => {
                attempts += 1;
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
            Err(e) => {
                return Err(e).context(format!(
                    "Failed to bind localhost:{}",
                    LOCAL_OAUTH_CALLBACK_PORT
                ))
            }
        }
    };
    info!(
        "OAuth callback server listening on localhost:{}",
        LOCAL_OAUTH_CALLBACK_PORT
    );

    let server_base_owned = server_base_url.to_string();
    let callback_state = SsoCallbackState {
        result_tx: callback_tx,
    };

    let app = Router::new()
        .route("/oauth/callback", get(handle_sso_callback))
        .with_state(Arc::new(callback_state));

    // Stopped whenever this function returns, including on timeout or error,
    // so the port is free for the next authentication round
    let _server = AbortOnDrop(tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .map_err(|e| error!("OAuth callback server error: {}", e))
            .ok();
    }));

    // Open browser
    let url_owned = auth_url.to_string();
    let browser_opened = tokio::task::spawn_blocking(move || try_open_browser(&url_owned))
        .await
        .unwrap_or(false);

    if browser_opened {
        info!("Browser opened for SSO authentication");
        show_notification(
            "VPN Authentication",
            "Please complete login in your browser...",
        );
    } else {
        warn!("Could not open browser automatically");
        show_notification(
            "VPN SSO Login Required",
            &format!("Please open: {}", auth_url),
        );
    }

    info!("SSO Login URL: {}", auth_url);

    // Wait for the callback with timeout (120 seconds to match AUTH_PENDING timeout)
    let result = tokio::time::timeout(std::time::Duration::from_secs(120), callback_rx)
        .await
        .map_err(|_| anyhow!("SSO authentication timed out after 120s"))?
        .map_err(|_| anyhow!("SSO callback channel dropped"))??;

    let (code, state) = result;
    info!("Received OAuth callback with state: {}", state);

    // POST the auth code to the VPN server
    let complete_url = format!("{}/auth/complete", server_base_owned);
    info!("Forwarding auth code to VPN server: {}", complete_url);

    let http_client = reqwest::Client::new();
    let response = http_client
        .post(&complete_url)
        .json(&serde_json::json!({
            "code": code,
            "state": state,
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .context("Failed to send auth code to VPN server")?;

    if response.status().is_success() {
        info!("VPN server accepted OAuth authentication");
        show_notification("VPN Authentication", "Login successful! VPN connecting...");
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        error!("VPN server rejected OAuth: {} - {}", status, body);
        return Err(anyhow!("VPN server rejected authentication: {}", body));
    }

    Ok(())
}

type SsoResultSender = Arc<tokio::sync::Mutex<Option<oneshot::Sender<Result<(String, String)>>>>>;

/// Shared state for the SSO callback handler
struct SsoCallbackState {
    result_tx: SsoResultSender,
}

/// Query parameters from Google's OAuth redirect
#[derive(Debug, Deserialize)]
struct SsoCallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Handle the OAuth callback from Google on localhost
async fn handle_sso_callback(
    State(state): State<Arc<SsoCallbackState>>,
    Query(params): Query<SsoCallbackParams>,
) -> impl IntoResponse {
    debug!(
        "Received OAuth callback on localhost: code={}, state={}, error={:?}",
        params
            .code
            .as_deref()
            .map(|c| &c[..c.len().min(10)])
            .unwrap_or("none"),
        params.state.as_deref().unwrap_or("none"),
        params.error
    );

    let tx = {
        let mut guard = state.result_tx.lock().await;
        guard.take()
    };

    if let Some(error) = params.error {
        let desc = params.error_description.unwrap_or_else(|| error.clone());
        if let Some(tx) = tx {
            let _ = tx.send(Err(anyhow!("OAuth error: {}", desc)));
        }
        return Html(error_page(&desc));
    }

    let code = match params.code {
        Some(c) => c,
        None => {
            if let Some(tx) = tx {
                let _ = tx.send(Err(anyhow!("No authorization code in callback")));
            }
            return Html(error_page("No authorization code received"));
        }
    };

    let oauth_state = params.state.unwrap_or_default();

    // Send the code + state to the main task
    if let Some(tx) = tx {
        let _ = tx.send(Ok((code, oauth_state)));
    }

    // Show a "please wait" page - the main task will POST to the VPN server
    Html(r#"<!DOCTYPE html>
<html><head><title>CoreVPN - Authenticating</title>
<style>body{font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#1a1a2e;color:#eee}
.card{background:#16213e;border-radius:12px;padding:40px;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.3)}
h1{color:#4ecca3;margin-bottom:10px}p{color:#aaa}.spinner{width:40px;height:40px;border:4px solid rgba(78,204,163,.2);border-top:4px solid #4ecca3;border-radius:50%;animation:spin 1s linear infinite;margin:20px auto}
@keyframes spin{to{transform:rotate(360deg)}}</style></head>
<body><div class="card"><div class="spinner"></div><h1>Authenticating...</h1>
<p>Completing VPN authentication. You can close this window shortly.</p></div>
<script>setTimeout(()=>{document.querySelector('h1').textContent='✓ Authenticated';document.querySelector('.spinner').style.display='none';document.querySelector('p').textContent='VPN connection is being established. You can close this window.'},3000)</script>
</body></html>"#.to_string())
}

/// Try to open a browser via systemd user path activation.
///
/// Writes the URL to `/run/nm-openvpn-sso/$UID/sso-{pid}.url` where the
/// `openvpn-sso-browser.service` (triggered by `openvpn-sso-browser.path`)
/// picks it up and runs `xdg-open` in the user's correct SELinux context.
///
/// The per-user subdirectory is chowned to the user so the service can
/// delete the URL file after processing.
///
/// Returns true if the URL file was written successfully.
fn try_open_browser(url: &str) -> bool {
    info!("Attempting to open browser for URL: {}", url);

    let uid = match find_graphical_user() {
        Some(ref user) => match get_uid_for_user(user) {
            Some(id) => id,
            None => {
                warn!("Could not get UID for user {}", user);
                return false;
            }
        },
        None => {
            warn!("Could not find graphical user session");
            return false;
        }
    };

    // Use /run/nm-openvpn-sso/$UID/ per-user subdirectories.
    // SELinux blocks NetworkManager_t from writing to user_tmp_t
    // (/run/user/$UID), but NetworkManager_t CAN write to
    // NetworkManager_var_run_t (/run/nm-openvpn-sso/).
    // The per-user directory is chowned to the user so their systemd
    // service can delete URL files after processing.
    let base_dir = "/run/nm-openvpn-sso";
    let user_dir = format!("{}/{}", base_dir, uid);

    if let Err(e) = std::fs::create_dir_all(base_dir) {
        warn!("Failed to create {}: {}", base_dir, e);
        return false;
    }

    if let Err(e) = std::fs::create_dir_all(&user_dir) {
        warn!("Failed to create {}: {}", user_dir, e);
        return false;
    }

    // Try to chown the per-user directory to the user so they can
    // manage files within it. Falls back to world-writable if chown
    // is denied by SELinux.
    if chown(&user_dir, Some(uid), Some(uid)).is_err() {
        warn!(
            "Failed to chown {} to uid {}, falling back to world-writable",
            user_dir, uid
        );
        if let Err(e) = std::fs::set_permissions(&user_dir, std::fs::Permissions::from_mode(0o777))
        {
            warn!("Failed to set permissions on {}: {}", user_dir, e);
            return false;
        }
    } else if let Err(e) =
        std::fs::set_permissions(&user_dir, std::fs::Permissions::from_mode(0o700))
    {
        warn!("Failed to set permissions on {}: {}", user_dir, e);
        return false;
    }

    let filename = format!("{}/sso-{}.url", user_dir, std::process::id());
    let temp_filename = format!("{}/.sso-{}.tmp", user_dir, std::process::id());
    match write_url_file(&temp_filename, &filename, url) {
        Ok(()) => {
            info!("Wrote URL to {} for systemd path activation", filename);
            true
        }
        Err(e) => {
            warn!("Failed to write URL file {}: {}", filename, e);
            false
        }
    }
}

/// Publish the URL file atomically: the path unit must never see a partially
/// written file. The directory may be world-writable (when chown is denied),
/// so create the temp file with O_EXCL, which refuses to follow a planted
/// symlink, and rename() over the destination, which replaces rather than
/// follows one.
fn write_url_file(temp_path: &str, path: &str, url: &str) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let _ = std::fs::remove_file(temp_path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(temp_path)?;
    file.write_all(url.as_bytes())?;
    drop(file);
    std::fs::rename(temp_path, path)
}

/// Find the username of an active graphical session
fn find_graphical_user() -> Option<String> {
    // Use loginctl to find active sessions
    let output = std::process::Command::new("loginctl")
        .args(["list-sessions", "--no-legend"])
        .output()
        .ok()?;

    let sessions = String::from_utf8_lossy(&output.stdout);
    info!("loginctl sessions: {}", sessions.trim());

    for line in sessions.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        let session_id = parts[0];
        let user = parts[2];

        // Skip root sessions
        if user == "root" {
            continue;
        }

        // Check session type and state
        let show_output = std::process::Command::new("loginctl")
            .args([
                "show-session",
                session_id,
                "-p",
                "Type",
                "-p",
                "State",
                "-p",
                "Active",
            ])
            .output()
            .ok()?;

        let session_info = String::from_utf8_lossy(&show_output.stdout);
        info!(
            "Session {} for {}: {}",
            session_id,
            user,
            session_info.replace('\n', " ")
        );

        // Check if graphical and active
        let is_graphical =
            session_info.contains("Type=x11") || session_info.contains("Type=wayland");
        let is_active =
            session_info.contains("Active=yes") || session_info.contains("State=active");

        if is_graphical && is_active {
            info!("Found active graphical session for user: {}", user);
            return Some(user.to_string());
        }
    }

    // Fallback: try to find any non-root user with an active session
    for line in sessions.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[2] != "root" {
            warn!("Using fallback non-graphical user: {}", parts[2]);
            return Some(parts[2].to_string());
        }
    }

    None
}

/// Get the UID for a username
fn get_uid_for_user(username: &str) -> Option<u32> {
    let output = std::process::Command::new("id")
        .args(["-u", username])
        .output()
        .ok()?;

    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

/// Show a desktop notification (non-blocking wrapper)
fn show_notification(summary: &str, body: &str) {
    let summary = summary.to_string();
    let body = body.to_string();

    // Spawn in background thread to avoid blocking
    std::thread::spawn(move || {
        if let Err(e) = Notification::new()
            .summary(&summary)
            .body(&body)
            .appname("OpenVPN SSO")
            .timeout(5000)
            .show()
        {
            // Can't use warn! here as it might not be set up for this thread
            eprintln!("Failed to show notification: {}", e);
        }
    });
}

/// HTML page for auth errors
fn error_page(message: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Authentication Failed</title>
    <style>
        body {{
            font-family: system-ui, -apple-system, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
        }}
        .container {{
            text-align: center;
            background: white;
            padding: 3rem;
            border-radius: 1rem;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }}
        .error-icon {{
            font-size: 4rem;
            color: #ef4444;
        }}
        h1 {{ color: #1f2937; margin: 1rem 0 0.5rem; }}
        p {{ color: #6b7280; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">✗</div>
        <h1>Authentication Failed</h1>
        <p>{}</p>
    </div>
</body>
</html>"#,
        html_escape(message)
    )
}

/// Escape text for HTML. The error page shows `error_description` from the
/// callback query string, which anyone can put in a localhost link.
fn html_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_localhost_callback_flow() {
        assert_eq!(
            localhost_callback_base(
                "https://vpn.example.com:9000/auth/start?redirect_uri=http://127.0.0.1:19823/oauth/callback"
            ),
            Some("https://vpn.example.com:9000".into())
        );
        // Percent-encoded redirect_uri (missed by the old substring check);
        // default port is not replaced by 9000
        assert_eq!(
            localhost_callback_base(
                "https://vpn.example.com/auth/start?redirect_uri=http%3A%2F%2Flocalhost%3A19823%2Fcb"
            ),
            Some("https://vpn.example.com".into())
        );
        // Native webauth: no redirect_uri, or one pointing elsewhere
        assert_eq!(
            localhost_callback_base("https://vpn.example.com:9000/oauth2/start?state=abc"),
            None
        );
        assert_eq!(
            localhost_callback_base(
                "https://idp.example.com/authorize?redirect_uri=https://vpn.example.com/callback"
            ),
            None
        );
    }

    #[test]
    fn error_page_escapes_message() {
        let page = error_page("<script>alert('x')</script>");
        assert!(!page.contains("<script>"));
        assert!(page.contains("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"));
    }
}
