\# How to Run a Zethora Seed Node



To help decentralize the network, community members can run a seed node on a Linux VPS (Ubuntu 22.04 or 24.04 recommended).



\## 1. Download the Linux Binary

Download the latest `kaspad` Linux binary from the GitHub Actions artifacts (or compile it from source using `cargo build --release --bin kaspad --target x86\_64-unknown-linux-musl`).



Upload it to your server:

scp -i /path/to/your/key.pem ./kaspad root@YOUR\_SERVER\_IP:/root/kaspad-linux



\## 2. Set up the Directory

SSH into your server and set up the folder and permissions:

mkdir -p /root/zethora

mv /root/kaspad-linux /root/zethora/kaspad

chmod +x /root/zethora/kaspad



\## 3. Create the Systemd Service

Create the service file so the node runs 24/7 in the background and auto-restarts if it crashes:

cat <<EOF > /etc/systemd/system/zethorad.service

\[Unit]

Description=Zethora Testnet Seed Node

After=network.target



\[Service]

Type=simple

User=root

WorkingDirectory=/root/zethora

ExecStart=/root/zethora/kaspad --testnet --utxoindex --nodnsseed

Restart=always

RestartSec=5

LimitNOFILE=65535



\[Install]

WantedBy=multi-user.target

EOF



\## 4. Open the Firewall

The testnet P2P port is `26211`. If you are using `ufw`, open it:

ufw allow 26211/tcp

ufw reload



\*(You must also ensure your VPS provider's external firewall allows TCP port 26211).\*



\## 5. Start the Node

systemctl daemon-reload

systemctl enable zethorad

systemctl start zethorad



\## 6. Verify

Check the status:

systemctl status zethorad



Watch the live logs to see peers connecting:

journalctl -u zethorad -f

