# The Sentinel Guide

Sentinels are the first line of defense and the foundation of the Zethora testnet. By running a node or mining, you are securing the network and earning testnet ZTHR.

## 1. How to Mine ZTHR
Zethora uses RandomZ, a CPU-friendly Proof-of-Work algorithm. You do not need a GPU. 

### Step 1: Get the Binary
Download zethora-miner-windows-v3.zip (or Linux equivalent) from the Discord #dev-updates channel.

### Step 2: Run the Miner
Open PowerShell and run:
.\zethora-miner.exe --testnet --node grpc://95.216.185.137:26210

The miner will generate a local key file (zethora-miner-key-testnet.txt) and begin hashing. 

## 2. How to Claim Testnet Tokens
Once your miner is running, look for the line that says Paying rewards to: zethoratest:.... Copy that address.

Go to the Faucet: http://95.216.185.137:8080
Paste your address and click **Claim 1 ZTHR**.

## 3. The Sentinel Role
If you run a node or mine on the testnet, post a screenshot in the #general-chat Discord channel. You will be granted the **Sentinel** role.

Sentinel benefits:
- Priority access to Mainnet whitelist.
- Token allocation from the Ecosystem Fund when Mainnet launches.
- Direct line to the core team for bug reports.

## 4. Troubleshooting
- **"Cannot reach node":** Check your internet connection and ensure port 26210 is not blocked by your router/firewall.
- **Miner stops instantly:** Check if your antivirus is blocking the .exe.
- **OOM Crash:** RandomZ requires about 2GB of RAM. Close background apps.