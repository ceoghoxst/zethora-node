#!/usr/bin/env bash
# Zethora seed node setup (step 7 / B7) for a fresh Ubuntu 22.04/24.04 server, e.g. an Oracle Cloud
# Always Free "Ampere A1" (ARM) or any x86 VPS. Run it as the normal login user (ubuntu), NOT as root:
#
#   curl -fsSL https://raw.githubusercontent.com/ceoghoxst/zethora-node/zethora/seed/setup-seed.sh | bash
#
# Re-running it is safe: it updates the code, re-checks RandomZ, rebuilds and restarts the node.
# What it does:
#   1. installs build tools and Rust, adds swap on small machines
#   2. downloads branch "zethora" of github.com/ceoghoxst/zethora-node into ~/zethora-node
#   3. checks RandomZ gives the exact same hashes on this CPU as on the PCs that made the test vectors (stops if not)
#   4. builds kaspad (the Zethora node) and installs it as /usr/local/bin/zethora-node
#   5. runs it as a background service "zethora-seed" (devnet), restarted automatically and at every boot
#   6. opens P2P port 26611 in this server's own firewall (the cloud firewall rule is added in the Oracle console)
# The node's RPC stays on 127.0.0.1 only: nobody on the internet can send it RPC commands.
set -euo pipefail
# Everything runs inside main(), called on the last line: if the download is cut off, nothing runs.
main() {

NETWORK_FLAG="--devnet"
P2P_PORT=26611
REPO_URL="https://github.com/ceoghoxst/zethora-node.git"
BRANCH="zethora"
SRC="$HOME/zethora-node"
DATA="$HOME/zethora-data"
BIN="/usr/local/bin/zethora-node"
SERVICE="zethora-seed"

say() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
fail() { printf '\n\033[1;31mFAILED: %s\033[0m\n' "$*"; exit 1; }

[ "$(id -u)" -ne 0 ] || fail "run this as your normal user (ubuntu), not as root"
command -v sudo >/dev/null || fail "sudo is missing"

say "1/6 Build tools"
sudo apt-get update -y </dev/null
# Note: on a non-Oracle server that uses ufw, iptables-persistent replaces ufw (Oracle images don't use ufw).
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential pkg-config libssl-dev protobuf-compiler libprotobuf-dev \
    clang libclang-dev llvm cmake git curl ca-certificates iptables-persistent </dev/null

mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
if [ "$mem_kb" -lt 8000000 ] && ! swapon --show | grep -q /swapfile; then
    say "Adding 6 GB swap (this machine has less than 8 GB RAM; building needs more)"
    sudo fallocate -l 6G /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
fi

if ! command -v cargo >/dev/null; then
    say "Installing Rust"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal </dev/null
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
rustup update stable >/dev/null </dev/null

say "2/6 Zethora code (branch $BRANCH)"
if [ -d "$SRC/.git" ]; then
    git -C "$SRC" fetch origin "$BRANCH" </dev/null
    git -C "$SRC" checkout -q "$BRANCH" 2>/dev/null || git -C "$SRC" checkout -q -b "$BRANCH" "origin/$BRANCH"
    git -C "$SRC" reset -q --hard "origin/$BRANCH"
else
    git clone --branch "$BRANCH" "$REPO_URL" "$SRC" </dev/null
fi
cd "$SRC"
echo "Code version: $(git log --oneline -1)"

say "3/6 RandomZ check on this CPU ($(uname -m)) - first build takes a while"
cargo test --release -p kaspa-pow --no-run </dev/null || fail "the RandomZ test build failed; send the first red error to Claude"
cargo test --release -p kaspa-pow randomz </dev/null || fail "RandomZ hashes differ on this CPU. Do not run a node here; send this output to Claude."

say "4/6 Building the node (30-60 min the first time on a 4-core ARM server)"
cargo build --release --bin kaspad </dev/null || fail "the node build failed; send the first red error to Claude"
sudo install -m 0755 target/release/kaspad "$BIN"

say "5/6 Background service '$SERVICE'"
PUBLIC_IP="$(curl -fsS --max-time 10 https://api.ipify.org || true)"
EXTERNAL=""
if [[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    EXTERNAL="--externalip=$PUBLIC_IP"
    echo "Public IP: $PUBLIC_IP"
else
    echo "Could not detect the public IP; the node will still work, it just won't advertise itself."
fi
mkdir -p "$DATA"
sudo tee /etc/systemd/system/$SERVICE.service >/dev/null <<EOF
[Unit]
Description=Zethora seed node ($NETWORK_FLAG)
After=network-online.target
Wants=network-online.target

[Service]
User=$(id -un)
# --yes: answer "yes" to database-reset questions (a service has no keyboard; without it a devnet reset in an update
# would make the node exit and restart forever). A seed keeps no wallet, so a reset only means re-downloading the chain.
ExecStart=$BIN $NETWORK_FLAG --appdir=$DATA --disable-upnp --yes $EXTERNAL
Restart=always
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE" >/dev/null
sudo systemctl restart "$SERVICE"

say "6/6 Opening P2P port $P2P_PORT in this server's firewall"
# Oracle's Ubuntu images end the INPUT chain with a REJECT rule, so the ACCEPT goes at the top.
if ! sudo iptables -C INPUT -p tcp --dport "$P2P_PORT" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null; then
    sudo iptables -I INPUT 1 -p tcp --dport "$P2P_PORT" -m conntrack --ctstate NEW -j ACCEPT
fi
sudo netfilter-persistent save >/dev/null 2>&1 || sudo sh -c 'iptables-save > /etc/iptables/rules.v4'

sleep 5
if systemctl is-active --quiet "$SERVICE"; then
    say "DONE: the Zethora seed node is running"
    echo "Seed address for the PC: --seed=${PUBLIC_IP:-THIS_SERVER_PUBLIC_IP}"
    echo "Watch it:  journalctl -u $SERVICE -f        (Ctrl+C stops watching, not the node)"
    echo "Stop it:   sudo systemctl stop $SERVICE"
else
    sudo journalctl -u "$SERVICE" -n 40 --no-pager
    fail "the service did not start; send the lines above to Claude"
fi
}

main "$@"
