#!/bin/bash
# SPDX-License-Identifier: MIT
#
# VPN SSO connection helper: list, connect, disconnect or toggle the
# NetworkManager connections that use the openvpn-sso plugin, from a
# terminal or (with kdialog) from a desktop launcher.
#
# Connections are handled by UUID internally, so names with spaces, colons
# or shell syntax are safe.

set -euo pipefail

SERVICE_TYPE="org.freedesktop.NetworkManager.openvpn-sso"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

notify() {
    notify-send "$@" 2>/dev/null || true
}

# Print the UUID of every openvpn-sso connection, one per line
get_sso_uuids() {
    local uuid type
    while IFS=: read -r uuid type; do
        [[ "$type" == "vpn" ]] || continue
        if [[ "$(nmcli -g vpn.service-type connection show uuid "$uuid" 2>/dev/null)" == "$SERVICE_TYPE" ]]; then
            printf '%s\n' "$uuid"
        fi
    done < <(nmcli -g UUID,TYPE connection show)
}

# Display name of a connection given by name or UUID
conn_name() {
    nmcli -e no -g connection.id connection show "$1" 2>/dev/null || printf '%s\n' "$1"
}

is_active() {
    [[ "$(nmcli -g GENERAL.STATE connection show "$1" 2>/dev/null)" == "activated" ]]
}

show_status() {
    local name
    name="$(conn_name "$1")"
    if is_active "$1"; then
        echo -e "${GREEN}●${NC} $name (connected)"
    else
        echo -e "${RED}○${NC} $name (disconnected)"
    fi
}

connect_vpn() {
    local name
    name="$(conn_name "$1")"
    echo -e "${YELLOW}Connecting to $name...${NC}"
    echo "Your browser will open for SSO authentication."
    if nmcli connection up "$1"; then
        echo -e "${GREEN}Connected to $name${NC}"
        notify "VPN Connected" "Connected to $name" -i network-vpn
    else
        echo -e "${RED}Failed to connect to $name${NC}"
        notify "VPN Connection Failed" "Failed to connect to $name" -i network-error
        return 1
    fi
}

disconnect_vpn() {
    local name
    name="$(conn_name "$1")"
    echo -e "${YELLOW}Disconnecting from $name...${NC}"
    if nmcli connection down "$1"; then
        echo -e "${GREEN}Disconnected from $name${NC}"
        notify "VPN Disconnected" "Disconnected from $name" -i network-offline
    else
        echo -e "${RED}Failed to disconnect from $name${NC}"
        return 1
    fi
}

toggle_vpn() {
    if is_active "$1"; then
        disconnect_vpn "$1"
    else
        connect_vpn "$1"
    fi
}

# Interactive menu: kdialog on a desktop, otherwise a terminal prompt
main() {
    local -a uuids
    mapfile -t uuids < <(get_sso_uuids)

    if ((${#uuids[@]} == 0)); then
        echo -e "${RED}No SSO VPN connections found.${NC}"
        echo "Import a connection with: nmcli connection import type openvpn file your-config.ovpn"
        echo "Then configure it: nmcli connection modify \"name\" vpn.service-type $SERVICE_TYPE"
        exit 1
    fi

    if ((${#uuids[@]} == 1)); then
        toggle_vpn "${uuids[0]}"
        return
    fi

    local uuid label choice
    if command -v kdialog >/dev/null && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
        # Arguments are passed as an array: no eval, no word splitting
        local -a menu=(--menu "Select VPN Connection")
        for uuid in "${uuids[@]}"; do
            if is_active "$uuid"; then
                label="● $(conn_name "$uuid") - connected, select to disconnect"
            else
                label="○ $(conn_name "$uuid") - disconnected, select to connect"
            fi
            menu+=("$uuid" "$label")
        done
        # Cancel exits kdialog with status 1
        choice="$(kdialog "${menu[@]}" 2>/dev/null)" || return 0
        if [[ -n "$choice" ]]; then
            toggle_vpn "$choice"
        fi
    else
        echo "SSO VPN Connections:"
        echo "===================="
        local i
        for i in "${!uuids[@]}"; do
            echo -n "  $((i + 1))) "
            show_status "${uuids[$i]}"
        done
        echo ""
        read -r -p "Enter number to toggle (or 'q' to quit): " choice || return 0
        if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#uuids[@]})); then
            toggle_vpn "${uuids[$((choice - 1))]}"
        fi
    fi
}

require_name() {
    if [[ -z "${2:-}" ]]; then
        echo "Usage: $0 $1 <connection-name>" >&2
        exit 1
    fi
}

case "${1:-}" in
    --list)
        while read -r uuid; do
            conn_name "$uuid"
        done < <(get_sso_uuids)
        ;;
    --status)
        while read -r uuid; do
            show_status "$uuid"
        done < <(get_sso_uuids)
        ;;
    --connect)
        require_name "$@"
        connect_vpn "$2"
        ;;
    --disconnect)
        require_name "$@"
        disconnect_vpn "$2"
        ;;
    --toggle)
        require_name "$@"
        toggle_vpn "$2"
        ;;
    --help | -h)
        echo "VPN SSO Connection Helper"
        echo ""
        echo "Usage: $0 [OPTION] [CONNECTION]"
        echo ""
        echo "Options:"
        echo "  --list              List all SSO VPN connections"
        echo "  --status            Show status of all SSO VPN connections"
        echo "  --connect NAME      Connect to specified VPN"
        echo "  --disconnect NAME   Disconnect from specified VPN"
        echo "  --toggle NAME       Toggle connection state"
        echo "  --help              Show this help"
        echo ""
        echo "Without arguments, shows an interactive menu."
        ;;
    *)
        main
        ;;
esac
