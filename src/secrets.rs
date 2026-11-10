// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

//! Cache of server auth-tokens, so a new connection can skip the browser
//! while the last token is still valid.
//!
//! The plugin runs as root under NetworkManager, outside any user session,
//! so the user's keyring is out of reach. Tokens are kept in root-only files
//! under /var/lib/nm-openvpn-sso.

use std::fs::{OpenOptions, Permissions};
use std::io::{ErrorKind, Write as _};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Root-only directory holding one `<connection-uuid>.json` per connection
const CACHE_DIR: &str = "/var/lib/nm-openvpn-sso";

/// A cached auth-token. Files written by earlier versions carry an unused
/// `refresh_token` field, which is ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredTokens {
    /// Server auth-token
    pub access_token: String,
    /// Expiry (Unix epoch seconds)
    pub expires_at: Option<i64>,
}

impl StoredTokens {
    /// Still valid for at least another minute
    pub fn is_valid(&self) -> bool {
        match self.expires_at {
            Some(expires) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                expires > now + 60
            }
            None => true,
        }
    }
}

fn cache_file(connection_uuid: &str) -> PathBuf {
    PathBuf::from(CACHE_DIR).join(format!("{connection_uuid}.json"))
}

/// The cached token for a connection, if there is one and it has not expired
pub async fn get_cached_credentials(connection_uuid: &str) -> Option<StoredTokens> {
    let path = cache_file(connection_uuid);
    let content = match tokio::fs::read_to_string(&path).await {
        Ok(content) => content,
        Err(e) if e.kind() == ErrorKind::NotFound => return None,
        Err(e) => {
            warn!("Failed to read token cache {}: {e}", path.display());
            return None;
        }
    };
    match serde_json::from_str::<StoredTokens>(&content) {
        Ok(tokens) if tokens.is_valid() => Some(tokens),
        Ok(_) => {
            debug!("Cached auth-token for {connection_uuid} has expired");
            None
        }
        Err(e) => {
            warn!("Ignoring unreadable token cache {}: {e}", path.display());
            None
        }
    }
}

/// Forget the cached token (the server rejected it)
pub async fn clear_cached_credentials(connection_uuid: &str) {
    match tokio::fs::remove_file(cache_file(connection_uuid)).await {
        Ok(()) => info!("Cleared cached auth-token for connection {connection_uuid}"),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => warn!("Failed to clear cached auth-token: {e}"),
    }
}

/// Cache a token after the server issued it
pub async fn cache_credentials(connection_uuid: &str, tokens: StoredTokens) -> Result<()> {
    let json = serde_json::to_vec(&tokens)?;
    write_private(
        Path::new(CACHE_DIR),
        &format!("{connection_uuid}.json"),
        &json,
    )
    .context("Failed to write token cache")?;
    info!("Cached auth-token for connection {connection_uuid}");
    Ok(())
}

/// Replace `dir/name` atomically with a root-only file. The token is never
/// readable by others, not even briefly, and never half-written.
fn write_private(dir: &Path, name: &str, contents: &[u8]) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, Permissions::from_mode(0o700))?;
    let temp = dir.join(format!(".{name}.tmp"));
    let _ = std::fs::remove_file(&temp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(contents)?;
    drop(file);
    std::fs::rename(&temp, dir.join(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn reads_caches_from_earlier_versions() {
        let old = r#"{"access_token":"SESS_ID_AT_x","refresh_token":null,"expires_at":1}"#;
        let tokens: StoredTokens = serde_json::from_str(old).unwrap();
        assert_eq!(tokens.access_token, "SESS_ID_AT_x");
        assert!(!tokens.is_valid());
    }

    #[test]
    fn writes_cache_files_privately() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("secrets-test-{}", std::process::id()));
        write_private(&dir, "a.json", b"one").unwrap();
        write_private(&dir, "a.json", b"two").unwrap();

        let path = dir.join("a.json");
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert!(!dir.join(".a.json.tmp").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
