# Mining on Zethora Devnet

Devnet is a private test network for the Zethora team. It is not public, coins have no value, and nothing carries over to testnet or mainnet. No token exists.

Once your node is running, you can start mining. The miner connects to your local node to get block templates and submits solved blocks.

## Prerequisites

- Your node (`kaspad`) must be running in a separate window.
- Your node must be using the `--enable-unsynced-mining` flag (this is in the Getting Started guide).

## Start the miner

Open a new PowerShell window and run:

    .\target\release\zethora-miner.exe

You should see output every time a block is found. The most important line is the supply check:

    Supply check ... BALANCED

If you see `BALANCED`, the miner has successfully mined a block, and the supply ledger correctly accounted for the reward.

## Fast Mode and Light Mode

Fast Mode is the default. It uses every CPU thread and builds a roughly 2 GiB dataset for the highest hash rate. It is the right choice on a capable desktop.

Light Mode uses only the 256 MiB cache and runs on two threads, so it needs far less RAM. It is slower, but it lets old PCs and small VPS machines mine without running out of memory. Turn it on with `--light`:

    .\target\release\zethora-miner.exe --light

## Mining against a remote node

By default the miner connects to a node on your own machine. To point it at a node elsewhere, for example a VPS you run, pass `--node` with the node's address:

    .\target\release\zethora-miner.exe --node grpc://YOUR.NODE.IP:26210

You can combine the two, for example a light miner on a laptop pointed at a remote node:

    .\target\release\zethora-miner.exe --node grpc://YOUR.NODE.IP:26210 --light

Zethora uses RandomZ, a CPU-friendly proof-of-work algorithm.
On a modern desktop CPU, you can expect roughly 1,000 to 1,500 hashes per second.
The devnet difficulty is set so that a normal home computer will find blocks regularly.

Devnet difficulty is set low for testing. This does not describe testnet or mainnet. Devnet coins have no value and do not carry over to testnet or mainnet.

## Stopping the miner

Press `Ctrl + C` in the miner window.

## Troubleshooting

**Miner says "Connection refused"**
The node is not running, or it is not finished starting up. Check the node window.

**Miner runs, but finds no blocks**
The network difficulty might be higher than your CPU's hash rate. Try leaving it running for a few minutes.