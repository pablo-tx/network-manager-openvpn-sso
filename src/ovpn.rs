// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Joseph R. Quinn

//! Safe handling of .ovpn files.
//!
//! OpenVPN runs as root, and a .ovpn file can make it run programs, load
//! libraries, write files and read files. NetworkManager lets unprivileged
//! users create connections that point at any file, so a file that root
//! does not control must not reach OpenVPN unchanged:
//!
//! * A *trusted* file (owned by root, writable only by root, in directories
//!   only root can change) is used in place, exactly as OpenVPN would use it.
//! * Any other file is read once and rewritten into a private copy:
//!   directives that run programs, load code or write files are dropped,
//!   files it references must be readable by the file's owner and are
//!   inlined, and OpenVPN is started with `--script-security 1`.

use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use tracing::{info, warn};

/// Largest .ovpn or referenced key file accepted
const MAX_FILE_SIZE: u64 = 1024 * 1024;

/// Directives that run programs, load code, write files or take over the
/// process. Dropped from files that root does not control.
const DENIED_DIRECTIVES: &[&str] = &[
    // Run programs
    "up",
    "down",
    "route-up",
    "route-pre-down",
    "ipchange",
    "tls-verify",
    "tls-crypt-v2-verify",
    "auth-user-pass-verify",
    "client-connect",
    "client-disconnect",
    "client-crresponse",
    "learn-address",
    "dns-updown",
    "script-security",
    "iproute",
    // Load code
    "plugin",
    "engine",
    "providers",
    "pkcs11-providers",
    // Write files, read server-side files, or take over the process
    "log",
    "log-append",
    "status",
    "writepid",
    "replay-persist",
    "ifconfig-pool-persist",
    "tls-export-cert",
    "tmp-dir",
    "client-config-dir",
    "auth-gen-token-secret",
    "cd",
    "chroot",
    "daemon",
    "inetd",
    "config",
    "dev-node",
];

/// Directives whose file argument is replaced with an inline block
const INLINE_FILE_DIRECTIVES: &[&str] = &[
    "ca",
    "cert",
    "key",
    "extra-certs",
    "dh",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "secret",
    "crl-verify",
    "auth-user-pass",
    "http-proxy-user-pass",
];

/// Directives whose file argument cannot be inlined; the path is checked
/// and made absolute
const PATH_DIRECTIVES: &[&str] = &["pkcs12", "askpass", "capath"];

/// The .ovpn file as passed to OpenVPN
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigFile {
    /// File given to `--config`
    pub path: PathBuf,
    /// Directory relative paths in the file resolve against (`--cd`)
    pub dir: Option<PathBuf>,
    /// Not under root's control: OpenVPN must not run user scripts
    pub untrusted: bool,
}

/// How the .ovpn file reaches OpenVPN
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prepared {
    /// Use the file where it is
    InPlace { path: PathBuf, dir: PathBuf },
    /// Write `text` to a private copy and use that
    Copy {
        text: String,
        /// Directory that relative paths in `text` resolve against
        dir: Option<PathBuf>,
        /// The original file is not under root's control
        untrusted: bool,
    },
}

/// Decide how to pass the .ovpn file at `path` to OpenVPN
pub fn prepare(path: &Path) -> Result<Prepared> {
    let path = std::fs::canonicalize(path)
        .with_context(|| format!("Cannot open OpenVPN config {}", path.display()))?;
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("OpenVPN config {} has no directory", path.display()))?
        .to_path_buf();
    let (meta, contents) = read_file(&path)
        .with_context(|| format!("Cannot read OpenVPN config {}", path.display()))?;
    let contents = String::from_utf8_lossy(&contents).into_owned();

    if root_controlled(&meta) && ancestors_root_controlled(&dir)? {
        return Ok(match strip_management_directives(&contents) {
            None => Prepared::InPlace { path, dir },
            Some(text) => {
                info!("Config file contains management directives, using a sanitized copy");
                Prepared::Copy {
                    text,
                    dir: Some(dir),
                    untrusted: false,
                }
            }
        });
    }

    info!(
        "{} is not controlled by root; using a restricted copy",
        path.display()
    );
    // A file others can write may contain anything: then only files that
    // everyone can read may be referenced
    let owner = (meta.mode() & 0o022 == 0).then_some(meta.uid());
    let sanitized = sanitize(&contents, &OwnerFiles { dir, owner })
        .with_context(|| format!("Refusing OpenVPN config {}", path.display()))?;
    for directive in &sanitized.dropped {
        warn!(
            "Ignoring `{directive}` in {}: only allowed in configs owned by root \
             (for example in /etc/openvpn/client/)",
            path.display()
        );
    }
    Ok(Prepared::Copy {
        text: sanitized.text,
        dir: None,
        untrusted: true,
    })
}

/// Owned by root and writable by nobody else
fn root_controlled(meta: &Metadata) -> bool {
    meta.uid() == 0 && meta.mode() & 0o022 == 0
}

fn ancestors_root_controlled(dir: &Path) -> Result<bool> {
    for ancestor in dir.ancestors() {
        let meta = std::fs::metadata(ancestor)
            .with_context(|| format!("Cannot inspect {}", ancestor.display()))?;
        if !root_controlled(&meta) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Open a file without following symlinks anywhere in the path. Callers
/// canonicalize first; a symlink that appears afterwards fails the open, so
/// the file read is the file that was checked.
fn open_no_symlinks(path: &Path) -> std::io::Result<File> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: open_how is plain data; all-zero is its documented default
    let mut how: libc::open_how = unsafe { std::mem::zeroed() };
    // O_NONBLOCK: a FIFO must not block the service; regular files ignore it
    how.flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NONBLOCK) as u64;
    how.resolve = libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_MAGICLINKS;
    // SAFETY: c_path is NUL-terminated and `how` is a valid open_how whose
    // size is passed alongside it
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            c_path.as_ptr(),
            &how as *const libc::open_how,
            std::mem::size_of::<libc::open_how>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the kernel returned a new descriptor that nothing else owns
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

/// Read a regular file, refusing symlinks and oversized files
fn read_file(path: &Path) -> Result<(Metadata, Vec<u8>)> {
    let file = open_no_symlinks(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    let mut contents = Vec::new();
    file.take(MAX_FILE_SIZE + 1).read_to_end(&mut contents)?;
    if contents.len() as u64 > MAX_FILE_SIZE {
        bail!("{} is larger than {MAX_FILE_SIZE} bytes", path.display());
    }
    Ok((meta, contents))
}

/// Access to the files a .ovpn file references
pub trait Files {
    /// Contents of a referenced file
    fn read(&self, name: &str) -> Result<String>;
    /// Absolute path of a referenced file or directory
    fn resolve(&self, name: &str) -> Result<PathBuf>;
}

/// Referenced files, resolved next to the .ovpn file and limited to what
/// its owner can read
struct OwnerFiles {
    dir: PathBuf,
    /// None when the .ovpn file is writable by others
    owner: Option<u32>,
}

impl OwnerFiles {
    fn canonical(&self, name: &str) -> Result<PathBuf> {
        let path = self.dir.join(name);
        std::fs::canonicalize(&path).with_context(|| format!("Cannot open {}", path.display()))
    }

    /// The owner can read the file: it, and every directory above it, is
    /// owned by them or open to everyone. Group permissions are not
    /// considered.
    fn check_readable(&self, path: &Path, meta: &Metadata) -> Result<()> {
        if self.owner == Some(0) {
            return Ok(());
        }
        let allowed =
            |meta: &Metadata, bit: u32| self.owner == Some(meta.uid()) || meta.mode() & bit != 0;
        let mut readable = allowed(meta, 0o004);
        for dir in path.ancestors().skip(1) {
            readable &= allowed(&std::fs::metadata(dir)?, 0o001);
        }
        if !readable {
            bail!(
                "{} is not readable by the owner of the .ovpn file",
                path.display()
            );
        }
        Ok(())
    }
}

impl Files for OwnerFiles {
    fn read(&self, name: &str) -> Result<String> {
        let path = self.canonical(name)?;
        let (meta, contents) =
            read_file(&path).with_context(|| format!("Cannot read {}", path.display()))?;
        self.check_readable(&path, &meta)?;
        String::from_utf8(contents).map_err(|_| anyhow!("{} is not a text file", path.display()))
    }

    fn resolve(&self, name: &str) -> Result<PathBuf> {
        let path = self.canonical(name)?;
        let meta = open_no_symlinks(&path)
            .and_then(|file| file.metadata())
            .with_context(|| format!("Cannot open {}", path.display()))?;
        self.check_readable(&path, &meta)?;
        Ok(path)
    }
}

/// A rewritten .ovpn file
#[derive(Debug)]
pub struct Sanitized {
    pub text: String,
    /// Names of the directives that were removed
    pub dropped: Vec<String>,
}

/// Rewrite a .ovpn file that root does not control: drop dangerous
/// directives, and inline (or check and make absolute) referenced files.
/// Fails when a reference cannot be made safe.
pub fn sanitize(contents: &str, files: &dyn Files) -> Result<Sanitized> {
    let mut out = String::with_capacity(contents.len());
    let mut dropped = Vec::new();
    let mut inline_block: Option<String> = None;

    for (index, line) in contents.lines().enumerate() {
        let line_no = index + 1;
        let trimmed = line.trim();

        // Contents of inline files (<ca>...</ca>) are data, not directives
        if let Some(block) = &inline_block {
            if trimmed.strip_prefix("</").and_then(|t| t.strip_suffix('>')) == Some(block) {
                inline_block = None;
            }
            push_line(&mut out, line);
            continue;
        }
        if let Some(tag) = trimmed.strip_prefix('<').and_then(|t| t.strip_suffix('>')) {
            // <connection> blocks hold directives and are filtered like the rest
            if !tag.starts_with('/') && tag != "connection" {
                inline_block = Some(tag.to_string());
            }
            push_line(&mut out, line);
            continue;
        }

        let tokens = tokenize(line);
        let Some(args) = directive_args(&tokens) else {
            push_line(&mut out, line);
            continue;
        };
        let name = args[0];

        if name.starts_with("management") || DENIED_DIRECTIVES.contains(&name) {
            dropped.push(name.to_string());
            continue;
        }

        let file_arg = args.get(1).copied().filter(|arg| *arg != "[inline]");
        match file_arg {
            Some(file) if INLINE_FILE_DIRECTIVES.contains(&name) => {
                // `crl-verify DIR dir` names a directory and cannot be inlined
                if name == "crl-verify" && args.get(2) == Some(&"dir") {
                    let path = files.resolve(file).with_context(|| at(line_no))?;
                    push_line(&mut out, &format!("crl-verify {} dir", quote(&path)));
                    continue;
                }
                let data = files.read(file).with_context(|| at(line_no))?;
                if data.lines().any(|l| l.trim_start().starts_with("</")) {
                    bail!("{}: {file} contains an inline end tag", at(line_no));
                }
                push_line(&mut out, &format!("<{name}>"));
                out.push_str(&data);
                if !data.ends_with('\n') {
                    out.push('\n');
                }
                push_line(&mut out, &format!("</{name}>"));
                // tls-auth and secret take the key direction as 2nd argument
                if let Some(direction) = args.get(2) {
                    if matches!(name, "tls-auth" | "secret") {
                        push_line(&mut out, &format!("key-direction {direction}"));
                    }
                }
            }
            Some(file) if PATH_DIRECTIVES.contains(&name) => {
                let path = files.resolve(file).with_context(|| at(line_no))?;
                let mut rewritten = format!("{name} {}", quote(&path));
                for arg in &args[2..] {
                    rewritten.push(' ');
                    rewritten.push_str(&quote(Path::new(arg)));
                }
                push_line(&mut out, &rewritten);
            }
            // The credentials file would be sent to the proxy as root.
            // `auto`, `auto-nct` and `stdin` read no file.
            _ if matches!(name, "http-proxy" | "socks-proxy")
                && args
                    .get(3)
                    .is_some_and(|arg| !matches!(*arg, "auto" | "auto-nct" | "stdin")) =>
            {
                bail!(
                    "{}: proxy credentials files are only allowed in configs owned by root",
                    at(line_no)
                );
            }
            _ => push_line(&mut out, line),
        }
    }

    Ok(Sanitized { text: out, dropped })
}

fn at(line_no: usize) -> String {
    format!("line {line_no}")
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

/// Quote a path for an OpenVPN config line
fn quote(path: &Path) -> String {
    let path = path.to_string_lossy();
    format!("\"{}\"", path.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The directive a line runs and its arguments. Like OpenVPN, accepts a
/// leading `--` and looks through `setenv opt` (which runs the directive
/// that follows and only ignores it when unknown).
fn directive_args(tokens: &[String]) -> Option<Vec<&str>> {
    let mut args: Vec<&str> = tokens.iter().map(String::as_str).collect();
    loop {
        let first = *args.first()?;
        args[0] = first.strip_prefix("--").unwrap_or(first);
        if args.len() > 2 && args[0] == "setenv" && args[1] == "opt" {
            args.drain(..2);
        } else {
            return Some(args);
        }
    }
}

/// Split a config line into tokens the way OpenVPN does: whitespace
/// separated, with "double" and 'single' quotes, backslash escapes outside
/// single quotes, and `#` or `;` at the start of a token beginning a
/// comment.
fn tokenize(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = line.chars();
    let mut current: Option<String> = None;
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('"') | None, '\\') => {
                if let Some(next) = chars.next() {
                    current.get_or_insert_with(String::new).push(next);
                }
            }
            (Some(_), c) => current.get_or_insert_with(String::new).push(c),
            (None, '"' | '\'') => {
                quote = Some(c);
                current.get_or_insert_with(String::new);
            }
            (None, c) if c.is_whitespace() => {
                if let Some(token) = current.take() {
                    tokens.push(token);
                }
            }
            (None, '#' | ';') if current.is_none() => break,
            (None, c) => current.get_or_insert_with(String::new).push(c),
        }
    }
    tokens.extend(current);
    tokens
}

/// Remove management directives from a trusted .ovpn file so they cannot
/// clash with ours. Returns None when there is nothing to remove.
pub fn strip_management_directives(contents: &str) -> Option<String> {
    let is_management = |line: &str| {
        directive_args(&tokenize(line)).is_some_and(|args| args[0].starts_with("management"))
    };
    if !contents.lines().any(is_management) {
        return None;
    }
    let mut text = String::with_capacity(contents.len());
    for line in contents.lines().filter(|line| !is_management(line)) {
        push_line(&mut text, line);
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Referenced files for tests: name -> contents. Missing names are
    /// unreadable.
    struct FakeFiles(HashMap<&'static str, &'static str>);

    impl Files for FakeFiles {
        fn read(&self, name: &str) -> Result<String> {
            self.0
                .get(name)
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow!("{name} is not readable by the owner of the .ovpn file"))
        }

        fn resolve(&self, name: &str) -> Result<PathBuf> {
            self.read(name)?;
            Ok(Path::new("/home/user/vpn").join(name))
        }
    }

    fn files(entries: &[(&'static str, &'static str)]) -> FakeFiles {
        FakeFiles(entries.iter().copied().collect())
    }

    #[test]
    fn drops_directives_that_run_code_or_write_files() {
        let config = "client\n\
                      remote vpn.example.com 1194\n\
                      script-security 2\n\
                      up /home/user/evil.sh\n\
                      --down \"/home/user/evil.sh\"\n\
                      setenv opt route-up /home/user/evil.sh\n\
                      plugin /home/user/evil.so\n\
                      log-append /etc/cron.d/evil\n\
                      management 127.0.0.1 7505\n\
                      config /home/user/other.ovpn\n\
                      setenv opt block-outside-dns\n\
                      # up /commented/out.sh\n\
                      pull-filter ignore \"route-gateway\"\n";
        let sanitized = sanitize(config, &files(&[])).unwrap();
        assert_eq!(
            sanitized.text,
            "client\n\
             remote vpn.example.com 1194\n\
             setenv opt block-outside-dns\n\
             # up /commented/out.sh\n\
             pull-filter ignore \"route-gateway\"\n"
        );
        assert_eq!(
            sanitized.dropped,
            [
                "script-security",
                "up",
                "down",
                "route-up",
                "plugin",
                "log-append",
                "management",
                "config"
            ]
        );
    }

    #[test]
    fn keeps_inline_blocks_and_filters_connection_blocks() {
        let config = "<ca>\n\
                      up this-is-certificate-data\n\
                      </ca>\n\
                      <connection>\n\
                      remote a.example.com\n\
                      up /home/user/evil.sh\n\
                      </connection>\n";
        let sanitized = sanitize(config, &files(&[])).unwrap();
        assert_eq!(
            sanitized.text,
            "<ca>\n\
             up this-is-certificate-data\n\
             </ca>\n\
             <connection>\n\
             remote a.example.com\n\
             </connection>\n"
        );
        assert_eq!(sanitized.dropped, ["up"]);
    }

    #[test]
    fn inlines_referenced_files() {
        let config = "ca \"my ca.crt\"\n\
                      tls-auth ta.key 1\n\
                      auth-user-pass creds.txt\n\
                      auth-user-pass\n\
                      key [inline]\n";
        let sanitized = sanitize(
            config,
            &files(&[
                ("my ca.crt", "CA DATA\n"),
                ("ta.key", "TA DATA"),
                ("creds.txt", "user\npass\n"),
            ]),
        )
        .unwrap();
        assert_eq!(
            sanitized.text,
            "<ca>\nCA DATA\n</ca>\n\
             <tls-auth>\nTA DATA\n</tls-auth>\nkey-direction 1\n\
             <auth-user-pass>\nuser\npass\n</auth-user-pass>\n\
             auth-user-pass\n\
             key [inline]\n"
        );
    }

    #[test]
    fn makes_non_inline_paths_absolute() {
        let sanitized = sanitize(
            "pkcs12 client.p12\ncrl-verify crls dir\n",
            &files(&[("client.p12", ""), ("crls", "")]),
        )
        .unwrap();
        assert_eq!(
            sanitized.text,
            "pkcs12 \"/home/user/vpn/client.p12\"\n\
             crl-verify \"/home/user/vpn/crls\" dir\n"
        );
    }

    #[test]
    fn refuses_files_the_owner_cannot_read() {
        let err = sanitize("client\nkey /etc/ssl/private/host.key\n", &files(&[])).unwrap_err();
        assert!(format!("{err:#}").contains("line 2"), "{err:#}");
    }

    #[test]
    fn refuses_files_that_would_end_the_inline_block() {
        let err = sanitize(
            "ca ca.crt\n",
            &files(&[("ca.crt", "x\n</ca>\nup /home/user/evil.sh\n")]),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("inline end tag"), "{err:#}");
    }

    #[test]
    fn refuses_proxy_credentials_files() {
        assert!(sanitize("http-proxy proxy 8080 /etc/shadow\n", &files(&[])).is_err());
        assert!(sanitize("socks-proxy proxy 1080 creds\n", &files(&[])).is_err());
        let allowed = "http-proxy proxy 8080 auto\nhttp-proxy proxy 8080\n";
        assert_eq!(sanitize(allowed, &files(&[])).unwrap().text, allowed);
    }

    #[test]
    fn tokenizes_like_openvpn() {
        assert_eq!(
            tokenize(r#"  ca "a b\"c" 'd\e' f\ g # comment"#),
            ["ca", "a b\"c", "d\\e", "f g"]
        );
        assert_eq!(tokenize("; comment"), Vec::<String>::new());
        assert_eq!(tokenize("remote host\r"), ["remote", "host"]);
        assert_eq!(tokenize("ca ''"), ["ca", ""]);
    }

    #[test]
    fn strips_management_directives_only_when_present() {
        assert_eq!(strip_management_directives("client\nremote x\n"), None);
        assert_eq!(
            strip_management_directives("client\nmanagement 127.0.0.1 7505\n  management-hold\n"),
            Some("client\n".to_string())
        );
    }
}
