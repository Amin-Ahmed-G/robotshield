#!/bin/bash
# Install the robot firewall on an arm64 gateway (NanoPi etc.) running
# Ubuntu 24.04. Run from a checkout of this repo, as root:
#
#   sudo ./deploy/nanopi/setup_nanopi.sh --keystore ~/robot_fw_keystore-gateway.tgz
#
# Options:
#   --keystore FILE   gateway keystore tarball from sros2/make_keystore.sh
#   --with-netplan    also write /etc/netplan/01-robot-firewall.yaml (prompts for
#                     the WiFi password; applied on next boot or `netplan apply`)
#   --force           skip the SSH lock-out safety check
#
# Idempotent: re-run after changing deploy/nanopi/firewall.env.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WS=/opt/robot_firewall_ws
KEYSTORE_TGZ=""
WITH_NETPLAN=0
FORCE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --keystore) KEYSTORE_TGZ=$2; shift 2 ;;
        --with-netplan) WITH_NETPLAN=1; shift ;;
        --force) FORCE=1; shift ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
[ "$(dpkg --print-architecture)" = arm64 ] || [ "$(dpkg --print-architecture)" = amd64 ] || {
    echo "ROS 2 Jazzy needs arm64 (or amd64); armhf boards are not supported" >&2; exit 1; }
. /etc/os-release
[ "$VERSION_CODENAME" = noble ] || { echo "Ubuntu 24.04 (noble) required" >&2; exit 1; }

[ -f "$HERE/firewall.env" ] || {
    echo "create $HERE/firewall.env from firewall.env.example first" >&2; exit 1; }
set -a; . "$HERE/firewall.env"; set +a
[ "$UNTRUSTED_DOMAIN" != "$TRUSTED_DOMAIN" ] || { echo "domains must differ" >&2; exit 1; }
export UNTRUSTED_RTPS="$((7400 + 250 * UNTRUSTED_DOMAIN))-$((7400 + 250 * UNTRUSTED_DOMAIN + 249))"
export TRUSTED_RTPS="$((7400 + 250 * TRUSTED_DOMAIN))-$((7400 + 250 * TRUSTED_DOMAIN + 249))"

# SIEM export: allow exactly udp://host:port out of the WiFi interface.
SIEM_OUTPUT_RULE="# SIEM export disabled (SIEM_SYSLOG empty)"
if [ -n "${SIEM_SYSLOG:-}" ]; then
    if [[ "$SIEM_SYSLOG" =~ ^udp://([0-9.]+):([0-9]+)$ ]]; then
        SIEM_OUTPUT_RULE="oifname \$WIFI_IF ip daddr ${BASH_REMATCH[1]} udp dport ${BASH_REMATCH[2]} accept"
    else
        echo "SIEM_SYSLOG must look like udp://192.168.1.60:514 (IPv4 address)" >&2; exit 1
    fi
fi
export SIEM_OUTPUT_RULE

# Safety: if we are on SSH, it must come from LAPTOP_IP or the new rules cut us off.
if [ -n "${SSH_CLIENT:-}" ] && [ "${SSH_CLIENT%% *}" != "$LAPTOP_IP" ] && [ $FORCE = 0 ]; then
    echo "You are connected over SSH from ${SSH_CLIENT%% *}, but LAPTOP_IP=$LAPTOP_IP." >&2
    echo "The firewall would lock this session out. Fix firewall.env or use --force." >&2
    exit 1
fi

echo "==> Packages"
if [ ! -f /etc/apt/sources.list.d/ros2.list ] && ! dpkg -s ros2-apt-source >/dev/null 2>&1; then
    apt-get update
    apt-get install -y curl gnupg
    curl -sSL https://raw.githubusercontent.com/ros/rosdistro/master/ros.key \
        -o /usr/share/keyrings/ros-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/ros-archive-keyring.gpg] http://packages.ros.org/ros2/ubuntu noble main" \
        > /etc/apt/sources.list.d/ros2.list
fi
apt-get update
apt-get install -y ros-jazzy-ros-base ros-jazzy-sros2 ros-jazzy-test-msgs \
    python3-colcon-common-extensions nftables chrony gettext-base

echo "==> Service user"
id robotfw >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin robotfw

echo "==> Build workspace in $WS"
mkdir -p "$WS/src"
rm -rf "$WS/src/monitor_py" "$WS/src/deploy"
cp -r "$REPO/src/monitor_py" "$WS/src/"
cp -r "$REPO/deploy" "$WS/src/deploy"
touch "$WS/src/deploy/COLCON_IGNORE"
(cd "$WS" && set +u && source /opt/ros/jazzy/setup.bash && colcon build --packages-select monitor_py)

if [ "${FIREWALL_IMPL:-rust}" = rust ]; then
    echo "==> Build Rust gateway (as ${SUDO_USER:-root}, needs Rust >= 1.85 from rustup)"
    BUILD_USER=${SUDO_USER:-root}
    if ! sudo -u "$BUILD_USER" -H bash -lc 'cargo --version' >/dev/null 2>&1; then
        echo "!!  cargo not found for $BUILD_USER. Install Rust first (as $BUILD_USER, not root):" >&2
        echo "!!    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2
        echo "!!  or set FIREWALL_IMPL=python in firewall.env." >&2
        exit 1
    fi
    sudo -u "$BUILD_USER" -H bash -lc "cd '$REPO/rust' && ./build.sh --release -p robot_firewall"
    install -D -m 0755 "$REPO/rust/target/release/robot_firewall" /usr/local/lib/robot_firewall/robot_firewall
fi

echo "==> Configuration in /etc/robot_firewall"
install -d -m 0750 -o root -g robotfw /etc/robot_firewall
install -m 0640 -o root -g robotfw "$HERE/firewall.env" /etc/robot_firewall/firewall.env
if [ ! -f /etc/robot_firewall/firewall_params.yaml ]; then
    install -m 0640 -o root -g robotfw "$REPO/src/monitor_py/config/firewall_params.yaml" \
        /etc/robot_firewall/firewall_params.yaml
    echo "    installed default firewall_params.yaml (edit limits for your robot)"
fi

if [ -n "$KEYSTORE_TGZ" ]; then
    rm -rf /etc/robot_firewall/keystore
    install -d -m 0750 -o root -g robotfw /etc/robot_firewall/keystore
    tar -C /etc/robot_firewall/keystore -xzf "$KEYSTORE_TGZ"
    chown -R root:robotfw /etc/robot_firewall/keystore
    chmod -R u=rwX,g=rX,o= /etc/robot_firewall/keystore
fi
if [ -n "$FIREWALL_ENCLAVE" ] && [ ! -d "/etc/robot_firewall/keystore/enclaves$FIREWALL_ENCLAVE" ]; then
    echo "!!  No keystore for enclave $FIREWALL_ENCLAVE: pass --keystore, or set" >&2
    echo "!!  FIREWALL_ENCLAVE= (empty) to run without DDS-Security (bench only)." >&2
    exit 1
fi

echo "==> Helper scripts"
install -d /usr/local/lib/robot_firewall
install -m 0755 "$HERE"/scripts/*.sh "$HERE"/scripts/*.py /usr/local/lib/robot_firewall/

echo "==> Kernel settings"
envsubst < "$HERE/templates/99-robot-firewall.conf.in" > /etc/sysctl.d/99-robot-firewall.conf
sysctl --system >/dev/null

echo "==> nftables"
envsubst < "$HERE/templates/nftables.conf.in" > /etc/nftables.conf.new
nft -c -f /etc/nftables.conf.new
[ -f /etc/nftables.conf ] && cp /etc/nftables.conf "/etc/nftables.conf.bak.$(date +%s)"
mv /etc/nftables.conf.new /etc/nftables.conf
systemctl enable --now nftables
nft -f /etc/nftables.conf

if [ $WITH_NETPLAN = 1 ]; then
    echo "==> netplan"
    read -rsp "WiFi password for $WIFI_SSID: " WIFI_PASSWORD; echo
    export WIFI_PASSWORD
    umask 077
    envsubst < "$HERE/templates/01-robot-firewall.yaml.in" > /etc/netplan/01-robot-firewall.yaml
    netplan generate
    echo "    written; run 'netplan apply' (or reboot) when you are on the console"
fi

if [ -n "${SUDO_USER:-}" ]; then
    echo "==> sudoers: let $SUDO_USER run the console's gateway buttons without a password"
    cat > /etc/sudoers.d/robot-firewall.new <<EOF_SUDO
# Robot firewall console buttons (nft counters, restart). Installed by setup_nanopi.sh.
$SUDO_USER ALL=(root) NOPASSWD: /usr/sbin/nft list counters table inet robot_fw, /usr/bin/systemctl restart robot-firewall
EOF_SUDO
    chmod 0440 /etc/sudoers.d/robot-firewall.new
    visudo -cf /etc/sudoers.d/robot-firewall.new >/dev/null && mv /etc/sudoers.d/robot-firewall.new /etc/sudoers.d/robot-firewall
fi

echo "==> systemd"
install -m 0644 "$HERE"/systemd/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now chrony robot-firewall-counters.service
systemctl enable robot-firewall.service
systemctl restart robot-firewall.service

echo
echo "Done (${FIREWALL_IMPL:-rust} gateway). Firewall starts in LOCKDOWN. From the laptop:"
echo "  source deploy/nanopi/sros2/laptop_env.sh ~/robot_fw_keystore $UNTRUSTED_DOMAIN"
echo "  rust/target/release/firewall_console --gateway $SUDO_USER@<this-ip>   # GUI"
echo "  (or: ros2 service call /firewall/rearm std_srvs/srv/Trigger)"
echo "Logs: journalctl -u robot-firewall -f   Incidents: /var/log/robot_firewall/incidents.jsonl"
