// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

//! Connection configuration parsing and management

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use tracing::debug;
use zbus::zvariant::{OwnedValue, Value};

use crate::ovpn::ConfigFile;

/// VPN connection settings extracted from NetworkManager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// Unique connection identifier (used for keyring storage)
    pub uuid: String,
    /// Human-readable connection name
    pub id: String,
    /// Path to the .ovpn configuration file (None for NM-imported connections)
    pub config_path: Option<PathBuf>,
    /// Optional server override
    pub remote: Option<String>,
    /// Optional port override
    pub port: Option<u16>,
    /// Optional protocol override (udp/tcp)
    pub protocol: Option<String>,
    /// Username for initial auth (placeholder for SSO)
    pub username: Option<String>,
    /// Password for initial auth (placeholder for SSO)
    pub password: Option<String>,
    /// Additional OpenVPN arguments. Not populated by `from_nm_settings` — no
    /// NetworkManager setting is mapped to this field today. It exists for
    /// programmatic use (e.g. callers constructing a `ConnectionConfig`
    /// directly) rather than end-user configuration via NM.
    pub extra_args: Vec<String>,
    /// CA certificate path (from vpn.data "ca")
    pub ca: Option<String>,
    /// Client certificate path (from vpn.data "cert")
    pub cert: Option<String>,
    /// Client key path (from vpn.data "key")
    pub key: Option<String>,
    /// TLS auth key path (from vpn.data "ta")
    pub ta: Option<String>,
    /// TLS auth key direction (from vpn.data "ta-dir")
    pub ta_dir: Option<String>,
    /// Cipher algorithm (from vpn.data "cipher")
    pub cipher: Option<String>,
    /// Auth/digest algorithm (from vpn.data "auth")
    pub auth: Option<String>,
    /// Tunnel device type (from vpn.data "dev")
    pub dev: Option<String>,
    /// Remote cert TLS check (from vpn.data "remote-cert-tls")
    pub remote_cert_tls: Option<String>,
    /// Connection type: tls, password, etc. (from vpn.data "connection-type")
    pub connection_type: Option<String>,
    /// TLS crypt key path (from vpn.data "tls-crypt")
    pub tls_crypt: Option<String>,
    /// TLS crypt V2 key path (from vpn.data "tls-crypt-v2")
    pub tls_crypt_v2: Option<String>,
    /// Minimum TLS version (from vpn.data "tls-version-min")
    pub tls_version_min: Option<String>,
    /// Verify x509 name (from vpn.data "verify-x509-name")
    pub verify_x509_name: Option<String>,
    /// Challenge response flags (from vpn.data "challenge-response-flags")
    pub challenge_response_flags: Option<String>,
}

impl ConnectionConfig {
    /// Parse connection settings from NetworkManager D-Bus format
    /// The format is a{sa{sv}} - dict of setting-name -> dict of key -> variant
    pub fn from_nm_settings(
        settings: &HashMap<String, HashMap<String, OwnedValue>>,
    ) -> Result<Self> {
        // Extract connection section
        let connection = settings
            .get("connection")
            .ok_or_else(|| anyhow!("Missing 'connection' settings section"))?;

        let uuid = get_string(connection, "uuid")?;
        let id = get_string(connection, "id").unwrap_or_else(|_| "OpenVPN SSO".to_string());

        // Extract VPN section
        let vpn = settings
            .get("vpn")
            .ok_or_else(|| anyhow!("Missing 'vpn' settings section"))?;

        // Get VPN data (nested dict)
        let vpn_data = get_string_dict(vpn, "data");

        let config_path = vpn_data.get("config").map(PathBuf::from);

        // Parse individual NM settings (used when config_path is None)
        let ca = vpn_data.get("ca").cloned();
        let cert = vpn_data.get("cert").cloned();
        let key = vpn_data.get("key").cloned();
        let ta = vpn_data.get("ta").cloned();
        let ta_dir = vpn_data.get("ta-dir").cloned();
        let cipher = vpn_data.get("cipher").cloned();
        let auth = vpn_data.get("auth").cloned();
        let dev = vpn_data.get("dev").cloned();
        let remote_cert_tls = vpn_data.get("remote-cert-tls").cloned();
        let connection_type = vpn_data.get("connection-type").cloned();
        let tls_crypt = vpn_data.get("tls-crypt").cloned();
        let tls_crypt_v2 = vpn_data.get("tls-crypt-v2").cloned();
        let tls_version_min = vpn_data.get("tls-version-min").cloned();
        let verify_x509_name = vpn_data.get("verify-x509-name").cloned();
        let challenge_response_flags = vpn_data.get("challenge-response-flags").cloned();

        // Validate: need either a config file or at least a CA cert
        if config_path.is_none() && ca.is_none() {
            return Err(anyhow!(
                "Missing OpenVPN config: need either vpn.data.config path or vpn.data.ca certificate"
            ));
        }

        let remote = vpn_data.get("remote").cloned();
        let port = vpn_data.get("port").and_then(|p| p.parse().ok());
        let protocol = vpn_data.get("proto").cloned();
        let username = vpn_data.get("username").cloned();

        // Get secrets section for password
        let vpn_secrets = get_string_dict(vpn, "secrets");
        let password = vpn_secrets.get("password").cloned();

        Ok(Self {
            uuid,
            id,
            config_path,
            remote,
            port,
            protocol,
            username,
            password,
            extra_args: Vec::new(),
            ca,
            cert,
            key,
            ta,
            ta_dir,
            cipher,
            auth,
            dev,
            remote_cert_tls,
            connection_type,
            tls_crypt,
            tls_crypt_v2,
            tls_version_min,
            verify_x509_name,
            challenge_response_flags,
        })
    }

    /// Whether OpenVPN should request a username/password: the profile sets
    /// a username, or (without a .ovpn file) uses a password connection
    /// type. A .ovpn file with its own `auth-user-pass` also triggers the
    /// request, answered with [`auth_username`](Self::auth_username).
    pub fn uses_credentials(&self) -> bool {
        self.username.is_some()
            || (self.config_path.is_none()
                && matches!(
                    self.connection_type.as_deref(),
                    Some("password" | "password-tls")
                ))
    }

    /// Username sent when OpenVPN requests credentials, both with
    /// placeholder passwords and with cached tokens. Both must use the same
    /// value: OpenVPN auth-tokens are bound to the username they were
    /// issued for.
    pub fn auth_username(&self) -> &str {
        self.username.as_deref().unwrap_or("oauth")
    }

    /// Placeholder password sent to start the SSO exchange
    pub fn auth_password(&self) -> &str {
        self.password.as_deref().unwrap_or("oauth")
    }

    /// Build OpenVPN command line arguments. `config_file` is the .ovpn
    /// file prepared by [`crate::ovpn::prepare`] when `config_path` is set.
    pub fn build_openvpn_args(
        &self,
        management_socket: &str,
        config_file: Option<&ConfigFile>,
    ) -> Vec<String> {
        let mut args = Vec::new();

        let config_file = config_file.cloned().or_else(|| {
            // Not prepared: treat the file as untrusted
            self.config_path.clone().map(|path| ConfigFile {
                path,
                dir: None,
                untrusted: true,
            })
        });
        if let Some(file) = config_file {
            // .ovpn file mode. --cd must come first: it applies to files
            // read after it, and OpenVPN otherwise resolves relative paths
            // in the file against the service's working directory.
            if let Some(dir) = &file.dir {
                args.extend(["--cd".to_string(), dir.to_string_lossy().into_owned()]);
            }
            args.extend([
                "--config".to_string(),
                file.path.to_string_lossy().into_owned(),
            ]);
            // Later options override the file's: no user scripts as root
            if file.untrusted {
                args.extend(["--script-security".to_string(), "1".to_string()]);
            }
        } else {
            // NM-imported mode: build from individual settings
            args.extend([
                "--client".to_string(),
                "--nobind".to_string(),
                "--dev".to_string(),
                self.dev.clone().unwrap_or_else(|| "tun".to_string()),
                "--persist-key".to_string(),
                "--persist-tun".to_string(),
                "--resolv-retry".to_string(),
                "infinite".to_string(),
            ]);

            if let Some(ref ca) = self.ca {
                args.extend(["--ca".to_string(), ca.clone()]);
            }
            if let Some(ref cert) = self.cert {
                args.extend(["--cert".to_string(), cert.clone()]);
            }
            if let Some(ref key) = self.key {
                args.extend(["--key".to_string(), key.clone()]);
            }
            if let Some(ref ta) = self.ta {
                args.push("--tls-auth".to_string());
                args.push(ta.clone());
                if let Some(ref dir) = self.ta_dir {
                    args.push(dir.clone());
                }
            }
            if let Some(ref cipher) = self.cipher {
                args.extend(["--cipher".to_string(), cipher.clone()]);
            }
            if let Some(ref auth) = self.auth {
                args.extend(["--auth".to_string(), auth.clone()]);
            }
            if let Some(ref remote_cert_tls) = self.remote_cert_tls {
                args.extend(["--remote-cert-tls".to_string(), remote_cert_tls.clone()]);
            }
            if let Some(ref tls_crypt) = self.tls_crypt {
                args.extend(["--tls-crypt".to_string(), tls_crypt.clone()]);
            }
            if let Some(ref tls_crypt_v2) = self.tls_crypt_v2 {
                args.extend(["--tls-crypt-v2".to_string(), tls_crypt_v2.clone()]);
            }
            if let Some(ref tls_version_min) = self.tls_version_min {
                args.extend(["--tls-version-min".to_string(), tls_version_min.clone()]);
            }
            if let Some(ref verify_x509_name) = self.verify_x509_name {
                // verify-x509-name can be "name:value" or just "value" with a type
                // NetworkManager stores it as a single string like "name:server_F6GFnpl7jNfqyFuq"
                if let Some((arg_type, name)) = verify_x509_name.split_once(':') {
                    args.extend([
                        "--verify-x509-name".to_string(),
                        name.to_string(),
                        arg_type.to_string(),
                    ]);
                } else {
                    args.extend(["--verify-x509-name".to_string(), verify_x509_name.clone()]);
                }
            }
            if let Some(ref challenge_response_flags) = self.challenge_response_flags {
                // challenge-response-flags=2 means use static challenge
                if challenge_response_flags == "2" {
                    args.extend([
                        "--static-challenge".to_string(),
                        "Authentication required".to_string(),
                        "0".to_string(),
                    ]);
                }
            }
        }

        // Announce SSO/webauth capability so the server knows to send AUTH_PENDING
        // with OPEN_URL instead of rejecting with empty credentials.
        args.extend([
            "--setenv".to_string(),
            "IV_SSO".to_string(),
            "webauth,openurl".to_string(),
        ]);

        // Only ask for credentials when the profile defines them; OpenVPN
        // then queries the management interface (--management-query-passwords).
        // Without them, connect like a stock client with an empty username:
        // SSO servers such as openvpn-auth-oauth2 then set the session
        // username themselves and push it with the auth-token
        // (auth-token-user), so renegotiation can reuse the token. A
        // placeholder username prevents that push, and the server rejects
        // the token at the next renegotiation.
        if self.uses_credentials() {
            args.push("--auth-user-pass".to_string());
        }

        // On an authentication failure (expired auth-token, SSO timeout)
        // restart and authenticate again instead of exiting.
        args.extend(["--auth-retry".to_string(), "interact".to_string()]);

        // Common: management interface, for root only (the socket itself is
        // created world-accessible). No --script-security: the plugin runs
        // no scripts, and a root-owned .ovpn file sets its own level.
        args.extend([
            "--management".to_string(),
            management_socket.to_string(),
            "unix".to_string(),
            "--management-client-user".to_string(),
            "root".to_string(),
            "--management-query-passwords".to_string(),
            "--management-hold".to_string(),
        ]);

        // Common: apply overrides
        if let Some(ref remote) = self.remote {
            args.extend(remote_args(remote));
        }

        if let Some(port) = self.port {
            args.extend(["--port".to_string(), port.to_string()]);
        }

        if let Some(ref proto) = self.protocol {
            args.extend(["--proto".to_string(), proto.clone()]);
        }

        args.extend(self.extra_args.clone());

        args
    }
}

/// Turn NetworkManager's `remote` value into OpenVPN `--remote host [port
/// [proto]]` arguments. NetworkManager stores `host[:port[:proto]]`, IPv6
/// hosts in brackets, several entries separated by commas or spaces.
fn remote_args(remote: &str) -> Vec<String> {
    let mut args = Vec::new();
    for entry in remote.split([',', ' ']).filter(|e| !e.is_empty()) {
        let parts: Vec<&str> = match entry.strip_prefix('[').and_then(|e| e.split_once(']')) {
            Some((host, rest)) => std::iter::once(host)
                .chain(rest.split(':').skip(1))
                .collect(),
            // A bare IPv6 address has no port
            None if entry.parse::<Ipv6Addr>().is_ok() => vec![entry],
            None => entry.split(':').collect(),
        };
        args.push("--remote".to_string());
        args.extend(
            parts
                .into_iter()
                .filter(|p| !p.is_empty())
                .take(3)
                .map(str::to_string),
        );
    }
    args
}

fn get_string(dict: &HashMap<String, OwnedValue>, key: &str) -> Result<String> {
    let value = dict
        .get(key)
        .ok_or_else(|| anyhow!("Missing key: {}", key))?;
    match value_as_str(value) {
        Some(s) if !s.is_empty() => Ok(s.to_string()),
        Some(_) => Err(anyhow!("Key {} is empty", key)),
        None => Err(anyhow!("Key {} is not a string", key)),
    }
}

/// Read a D-Bus string, looking through a variant wrapper if present
fn value_as_str<'a>(value: &'a Value<'_>) -> Option<&'a str> {
    match value {
        Value::Str(s) => Some(s.as_str()),
        Value::Value(inner) => value_as_str(inner),
        _ => None,
    }
}

/// Read an `a{ss}` entry such as vpn.data or vpn.secrets. Values are never
/// logged: vpn.secrets holds passwords.
fn get_string_dict(dict: &HashMap<String, OwnedValue>, key: &str) -> HashMap<String, String> {
    let Some(Value::Dict(entries)) = dict.get(key).map(|v| &**v) else {
        return HashMap::new();
    };
    let result: HashMap<String, String> = entries
        .iter()
        .filter_map(|(k, v)| Some((value_as_str(k)?.to_string(), value_as_str(v)?.to_string())))
        .collect();
    debug!("vpn.{} keys: {:?}", key, result.keys().collect::<Vec<_>>());
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(value: Value<'_>) -> OwnedValue {
        value.try_into().unwrap()
    }

    fn string_map(pairs: &[(&str, &str)]) -> OwnedValue {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        owned(Value::from(map))
    }

    /// Settings shaped like NetworkManager's a{sa{sv}} Connect() argument
    fn nm_settings(data: &[(&str, &str)]) -> HashMap<String, HashMap<String, OwnedValue>> {
        let connection = HashMap::from([
            ("uuid".to_string(), owned(Value::from("a815ec0b-0000"))),
            ("id".to_string(), owned(Value::from("corp \"prod\""))),
        ]);
        let vpn = HashMap::from([
            ("data".to_string(), string_map(data)),
            ("secrets".to_string(), string_map(&[])),
        ]);
        HashMap::from([
            ("connection".to_string(), connection),
            ("vpn".to_string(), vpn),
        ])
    }

    #[test]
    fn parses_nm_settings() {
        let config =
            ConnectionConfig::from_nm_settings(&nm_settings(&[("config", "/etc/vpn/prod.ovpn")]))
                .unwrap();
        assert_eq!(config.uuid, "a815ec0b-0000");
        // Quotes in values survive (the old Display-based parsing stripped them)
        assert_eq!(config.id, "corp \"prod\"");
        assert_eq!(
            config.config_path,
            Some(PathBuf::from("/etc/vpn/prod.ovpn"))
        );
        assert_eq!(config.auth_username(), "oauth");
        assert_eq!(config.auth_password(), "oauth");
    }

    #[test]
    fn requires_config_file_or_ca() {
        assert!(ConnectionConfig::from_nm_settings(&nm_settings(&[])).is_err());
    }

    #[test]
    fn openvpn_args_without_username_send_no_credentials() {
        // Like a stock client: an empty username lets the SSO server set the
        // session username and push it with the auth-token
        let config =
            ConnectionConfig::from_nm_settings(&nm_settings(&[("config", "/etc/vpn/prod.ovpn")]))
                .unwrap();
        assert!(!config.uses_credentials());
        let args = config.build_openvpn_args("/run/nm-openvpn-sso/x.sock", None);
        let joined = args.join(" ");
        assert!(joined.starts_with("--config /etc/vpn/prod.ovpn "));
        assert!(!args.iter().any(|a| a == "--auth-user-pass"));
        assert!(joined.contains("--auth-retry interact"));
        assert!(joined.contains(
            "--management /run/nm-openvpn-sso/x.sock unix --management-client-user root \
             --management-query-passwords --management-hold"
        ));
    }

    #[test]
    fn openvpn_args_with_username_request_credentials() {
        let config = ConnectionConfig::from_nm_settings(&nm_settings(&[
            ("config", "/etc/vpn/prod.ovpn"),
            ("username", "pablo@example.com"),
        ]))
        .unwrap();
        assert!(config.uses_credentials());
        assert_eq!(config.auth_username(), "pablo@example.com");
        let joined = config
            .build_openvpn_args("/run/nm-openvpn-sso/x.sock", None)
            .join(" ");
        assert!(joined.contains("--auth-user-pass --auth-retry interact"));
    }

    #[test]
    fn requires_connection_section() {
        let mut settings = nm_settings(&[("config", "/etc/vpn/prod.ovpn")]);
        settings.remove("connection");
        let err = ConnectionConfig::from_nm_settings(&settings)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("Missing 'connection' settings section"),
            "{err}"
        );
    }

    #[test]
    fn openvpn_args_for_nm_imported_settings() {
        let config = ConnectionConfig::from_nm_settings(&nm_settings(&[
            ("ca", "/etc/openvpn/client/ca.crt"),
            ("cert", "/etc/openvpn/client/client.crt"),
            ("key", "/etc/openvpn/client/client.key"),
            ("ta", "/etc/openvpn/client/ta.key"),
            ("ta-dir", "1"),
            ("remote", "vpn.example.com:1194"),
            ("proto", "udp"),
        ]))
        .unwrap();
        assert!(config.config_path.is_none());
        let args = config.build_openvpn_args("/run/nm-openvpn-sso/x.sock", None);
        let has = |expected: &[&str]| args.windows(expected.len()).any(|w| w == expected);
        assert!(has(&["--client"]));
        assert!(!has(&["--config"]));
        assert!(has(&["--ca", "/etc/openvpn/client/ca.crt"]));
        assert!(has(&["--cert", "/etc/openvpn/client/client.crt"]));
        assert!(has(&["--key", "/etc/openvpn/client/client.key"]));
        assert!(has(&["--tls-auth", "/etc/openvpn/client/ta.key", "1"]));
        // NetworkManager stores "host:port"; OpenVPN wants --remote host port
        assert!(has(&["--remote", "vpn.example.com", "1194"]));
        assert!(has(&["--proto", "udp"]));
    }

    #[test]
    fn openvpn_args_for_prepared_config_files() {
        let config =
            ConnectionConfig::from_nm_settings(&nm_settings(&[("config", "/etc/vpn/prod.ovpn")]))
                .unwrap();
        let trusted = ConfigFile {
            path: PathBuf::from("/etc/vpn/prod.ovpn"),
            dir: Some(PathBuf::from("/etc/vpn")),
            untrusted: false,
        };
        let args = config.build_openvpn_args("/run/x.sock", Some(&trusted));
        assert_eq!(
            args[..4],
            ["--cd", "/etc/vpn", "--config", "/etc/vpn/prod.ovpn"]
        );
        // A root-owned file keeps its own script-security level
        assert!(!args.iter().any(|a| a == "--script-security"));

        let copy = ConfigFile {
            path: PathBuf::from("/run/nm-openvpn-sso/copy.ovpn"),
            dir: None,
            untrusted: true,
        };
        let args = config.build_openvpn_args("/run/x.sock", Some(&copy));
        assert_eq!(
            args[..4],
            [
                "--config",
                "/run/nm-openvpn-sso/copy.ovpn",
                "--script-security",
                "1"
            ]
        );
        assert_eq!(args.iter().filter(|a| *a == "--script-security").count(), 1);
    }

    #[test]
    fn splits_nm_remote_entries() {
        assert_eq!(
            remote_args("vpn.example.com"),
            ["--remote", "vpn.example.com"]
        );
        assert_eq!(
            remote_args("a.example.com:1194:udp, b.example.com:443:tcp"),
            [
                "--remote",
                "a.example.com",
                "1194",
                "udp",
                "--remote",
                "b.example.com",
                "443",
                "tcp"
            ]
        );
        assert_eq!(
            remote_args("[2001:db8::1]:1194"),
            ["--remote", "2001:db8::1", "1194"]
        );
        assert_eq!(remote_args("2001:db8::1"), ["--remote", "2001:db8::1"]);
    }
}
