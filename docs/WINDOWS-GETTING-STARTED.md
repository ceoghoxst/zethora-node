# Zethora Devnet on Windows - Getting Started

Devnet is a private test network for the Zethora team. It is not public, coins have no value, and nothing carries over to testnet or mainnet. No token exists.

This guide takes a fresh Windows PC to a running Zethora devnet node and miner.

## What you need

- Windows 10 or 11 (64-bit)
- 8 GB RAM minimum (16 GB recommended)
- 50 GB free disk space
- A stable internet connection

## Step 1: Install the toolchain

We need six things: Git, Rust, MSVC Build Tools, LLVM, Protobuf, and CMake.

**Important:** Run these install commands in an Administrator PowerShell window.

    winget install --id Git.Git -e --source winget
    winget install --id Rustlang.Rustup -e --source winget
    winget install --id Kitware.CMake -e --source winget

After installing Rust, you must set the default toolchain:

    rustup default stable

Next, install Visual Studio Build Tools with the C++ workload. This is the largest download (~5 GB):

    winget install --id Microsoft.VisualStudio.2022.BuildTools -e --source winget --override "--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"

Install LLVM and Protobuf:

    winget install --id LLVM.LLVM -e --source winget
    winget install --id Google.Protobuf -e --source winget

**CRITICAL:** Close PowerShell and open a fresh window so the PATH updates take effect.

## Step 2: Check your system clock

If your PC has been off for a while, the clock might drift. Rust requires a correct clock to download securely. Run this to sync:

    w32tm /resync

## Step 3: Clone the repository

    cd $env:USERPROFILE
    git clone https://github.com/ceoghoxst/zethora-node
    cd zethora-node
    git checkout zethora

## Step 4: Build the node

This will take 45 minutes to 1.5 hours on an average PC.

    $env:CARGO_BUILD_JOBS = "2"
    cargo build --release --bin kaspad

## Step 5: Run the devnet

Leave this window open. The node will run and sync.

    .\target\release\kaspad.exe --devnet --utxoindex --enable-unsynced-mining --reset-db --yes

You should see:
`GRPC Server starting on: 127.0.0.1:26610`
`P2P Server starting on: 0.0.0.0:26611`

## Step 6: Build and run the miner

Open a **second** PowerShell window.

    cd $env:USERPROFILE\zethora-node
    $env:CARGO_BUILD_JOBS = "2"
    cargo build --release -p zethora-miner

This takes about 20-40 minutes. When it finishes, start mining:

    .\target\release\zethora-miner.exe

You should see lines saying `Supply check ... BALANCED`.

## Troubleshooting

**"linker link.exe not found"**
Visual Studio Build Tools didn't finish installing, or you haven't restarted PowerShell. Restart your terminal and try again.

**"is cmake not installed?"**
You missed the CMake step. Run `winget install --id Kitware.CMake -e --source winget`, close the terminal, and try again.

**"invalid peer certificate: Expired"**
Your system clock is wrong. Run `w32tm /resync` and try again.

**Node crashes immediately on start**
You need to reset the devnet database. Add `--reset-db --yes` to your kaspad command.
---

## Alternative: Running with Docker

If you have [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed, you can run a Zethora node without installing Rust, Clang, or CMake.

The binary inside the container is kaspad (the devnet name). The zethora-node.exe name is only used in the release zip.

### 1. Build the Docker Image
Open PowerShell in the root of the `zethora-node` repository and run:

    docker build -t zethora-node .

*(This will compile the node inside a Linux container. It takes about 10-15 minutes the first time).*

### 2. Run the Node
Once the image is built, start the node:

    docker run -d --name zethora-node -p 26611:26611 -p 26610:26610 zethora-node

### 3. View the Logs
To see what the node is doing:

    docker logs -f zethora-node

You should see `P2P Server starting on: 0.0.0.0:26611`.
