# NetworkManager OpenVPN SSO Plugin

A NetworkManager VPN plugin that adds OAuth 2.0 / OIDC Single Sign-On (SSO) support for OpenVPN connections.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This is a fork focused on SELinux compatibility, reliable browser launch via systemd path activation, and proper VPN teardown.

## Fork Features

- **SELinux-safe browser launch** — Instead of launching the browser directly from `NetworkManager_t` context (which is blocked by SELinux from accessing user session D-Bus), the plugin writes the SSO URL to `/run/nm-openvpn-sso/$UID/` and triggers a **systemd user path unit** that opens the browser as the logged-in user.
- **systemd path activation** — No continuous watcher daemons. Uses kernel inotify via `systemd.path(5)` to detect new URL files and launch the browser via `xdg-open`. The service exits after processing and the path unit reactivates on new files.
- **Works with Flatpak browsers** — Since the browser is launched from the user's systemd session (not from `NetworkManager_t`), `xdg-open` resolves Flatpak-installed browsers correctly.
- **Proper VPN teardown** — `OpenVpnManager` is shared via `Arc<Mutex<>>` so `disconnect()` actually kills the OpenVPN process, cleaning up the TUN device and routes.
- **Smart SSO flow detection** — Automatically detects native OpenVPN webauth (`AUTH_PENDING` without localhost callback) vs callback flow (URL contains `redirect_uri=127.0.0.1`). Handles both gracefully.
- **Config file sanitization** — Removes `management` directives from imported `.ovpn` files before passing them to OpenVPN, preventing conflicts with the plugin's management interface.
- **No session token caching** — Every connection triggers the SSO browser flow. No stale token edge cases.
- **Full NetworkManager integration** — Works with `nmcli`, GNOME Settings, and KDE Plasma (via plasma-nm UI plugin).

## Installation

### Fedora / RHEL

```bash
sudo dnf install networkmanager-openvpn-sso-*.x86_64.rpm
```

The systemd path unit is auto-enabled during RPM install via `post_install` scriptlet.

### Arch Linux

```bash
sudo pacman -U networkmanager-openvpn-sso-*.pkg.tar.zst
```

### Other Linux Distributions

```bash
# Download and extract
tar -xzf nm-openvpn-sso-service-linux-x86_64.tar.gz

# Run the install script
sudo ./install.sh
```

### Systemd Units

The installation includes two systemd user units:

- **`openvpn-sso-browser.path`** — Watches `/run/nm-openvpn-sso/$(id -u)/*.url` for new SSO URL files
- **`openvpn-sso-browser.service`** — Reads the URL, opens it via `xdg-open`, deletes the file

These must be enabled (manually or via packaging scriptlets):

```bash
systemctl --user enable openvpn-sso-browser.path
systemctl --user start openvpn-sso-browser.path
```

The RPM handles this automatically via `post_install` / `pre_uninstall`.

## Usage

### Importing an OpenVPN Configuration

1. Import your `.ovpn` file:

```bash
nmcli connection import type openvpn file your-vpn-config.ovpn
```

2. Update to use the SSO plugin:

```bash
nmcli connection modify "your-vpn-name" vpn.service-type org.freedesktop.NetworkManager.openvpn-sso
```

3. Connect:

```bash
nmcli connection up "your-vpn-name"
```

Your default browser will open for SSO authentication. After successful login, the VPN connection will be established automatically.

### Using with Network Manager GUI

#### GNOME

The VPN connection appears in network settings and can be activated from there.

#### KDE Plasma

This fork includes the upstream's plasma-nm UI plugin for KDE Plasma integration. Build with KDE dependencies:

```bash
sudo dnf install extra-cmake-modules kf6-kcoreaddons-devel kf6-ki18n-devel kf6-kio-devel kf6-networkmanager-qt-devel NetworkManager-libnm-devel plasma-nm
sudo ./install.sh
```

## Requirements

- NetworkManager
- OpenVPN
- D-Bus
- systemd (user session)
- A graphical session (for browser-based authentication)

## SELinux

This fork is designed to work on Fedora with SELinux enforcing.

**The problem:** When NetworkManager spawns the VPN plugin, it runs as `NetworkManager_t`. This context:
- Cannot connect to the user's D-Bus session (required for `xdg-open`, `kdialog`, `notify-rust`)
- Cannot write to `/run/user/$UID/` (which is `user_tmp_t`)
- Cannot execute `runuser` or `machinectl` to escape its context

**The solution:**
1. The plugin creates `/run/nm-openvpn-sso/$UID/` (type `NetworkManager_var_run_t` — writable by `NetworkManager_t`)
2. Writes the SSO URL to `sso-{pid}.url`
3. Chowns the directory to the user so the user's systemd service can delete files
4. The systemd user path unit detects the file and launches `xdg-open` from `unconfined_t` (user domain), which has full access to user D-Bus and `NetworkManager_var_run_t`

## Troubleshooting

### Browser doesn't open

Check the plugin logs:

```bash
journalctl -u NetworkManager -f | grep nm-openvpn-sso
```

Check the systemd user service:

```bash
journalctl --user -u openvpn-sso-browser.service -f
```

Verify the URL file was created:

```bash
ls -la /run/nm-openvpn-sso/$(id -u)/
```

### SELinux denials

```bash
sudo ausearch -m avc -ts recent
sudo sealert -a /var/log/audit/audit.log
```

### VPN connects but no network access

Verify routes are correctly applied after disconnect:

```bash
ip route | grep tun
```

If TUN devices persist after disconnect, the OpenVPN process wasn't properly killed. Check logs for:

```
Disconnect called
Stopping OpenVPN process
```

If "Stopping OpenVPN process" is missing, the `OpenVpnManager` was inaccessible (Arc<Mutex> race). This is fixed in the current version.

### Connection times out

```bash
journalctl -u NetworkManager -f
journalctl --user -u openvpn-sso-browser.service -f
```

## How It Works

1. NetworkManager activates the VPN connection
2. The plugin starts OpenVPN with management interface enabled
3. OpenVPN connects to the server and receives an SSO authentication URL
4. The plugin writes the URL to `/run/nm-openvpn-sso/$UID/sso-{pid}.url`
5. The systemd path unit (`openvpn-sso-browser.path`) detects the new file and activates the service
6. The systemd service reads the URL, runs `xdg-open` to launch the browser, and deletes the file
7. The plugin detects the flow type:
   - **Callback flow** (redirect_uri=localhost): Starts a localhost HTTP server, opens browser to auth URL, receives the OAuth callback, POSTs the code to the VPN server
   - **Native webauth** (no localhost redirect): Just opens the browser; the server completes authentication through the VPN tunnel
8. After successful authentication, the server provides credentials and the plugin completes the VPN connection

### Disconnect Flow

1. User clicks disconnect in NetworkManager
2. The plugin sends `signal SIGTERM` to OpenVPN via the management interface
3. OpenVPN shuts down gracefully, cleaning up the TUN device and routes
4. The plugin cleans up the management socket and temporary config file

## Building from Source

### Prerequisites

```bash
# Fedora
sudo dnf install rust cargo dbus-devel openssl-devel pkg-config

# For KDE Plasma integration (optional)
sudo dnf install cmake extra-cmake-modules qt6-qtbase-devel kf6-kcoreaddons-devel kf6-ki18n-devel kf6-kio-devel kf6-networkmanager-qt-devel NetworkManager-libnm-devel plasma-nm

# Arch Linux
sudo pacman -S rust cargo dbus openssl pkgconf

# For KDE Plasma integration (optional)
sudo pacman -S extra-cmake-modules qt6-base networkmanager-qt kio ki18n kcoreaddons plasma-nm
```

### Build

```bash
git clone https://github.com/pegasusheavy/network-manager-openvpn-sso.git
cd network-manager-openvpn-sso
cargo build --release
```

### Install

```bash
sudo ./install.sh
```

### Uninstall

```bash
sudo ./uninstall.sh
```

## License

MIT License - see [LICENSE](LICENSE) for details.
