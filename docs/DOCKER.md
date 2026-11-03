# Running Zethora with Docker

This page shows how to run a Zethora testnet node and miner in containers
with `docker-compose up -d`.

Testnet coins are worth zero. This is a practice network for testing.

## Before you start

You need:

- Docker Engine 20.10 or newer, with the Compose v2 plugin.
- The three **pre-built Linux binaries** in the `bin/` folder of this
  repository:

      bin/zethora-node
      bin/zethora-miner
      bin/zethora-wallet

  The Docker image does not compile anything. It copies exactly these
  three files into an `ubuntu:22.04` image, so they must exist before you
  build. Prebuilt Windows `.exe` files are **not** used: the image needs
  the Linux (ELF x86-64) builds.

Check Docker is installed:

    docker --version
    docker compose version

## Quick start

From the repository root, start everything in the background:

    docker-compose up -d

That single command:

1. Builds the image from the `Dockerfile` (once).
2. Starts `zethora-node` with `--testnet --utxoindex`.
3. Starts `zethora-miner` with `--testnet`, after the node is up.

Check that both are running:

    docker-compose ps

Follow the node log:

    docker-compose logs -f zethora-node

Follow the miner log:

    docker-compose logs -f zethora-miner

The miner prints a line every time it finds a block. The line to look for
is the supply check:

    Supply check ... BALANCED

If you see `BALANCED`, the miner found a block and the supply ledger
accounted for the reward correctly.

## Stopping

Stop the containers but keep their data:

    docker-compose down

Stop and also delete the node database and the miner key file:

    docker-compose down -v

## Ports

The node publishes two ports on your machine:

| Port  | What it is            | Flag        |
|-------|-----------------------|-------------|
| 16211 | testnet peer-to-peer  | `--testnet` |
| 26210 | testnet gRPC / RPC    | `--testnet` |

The miner and wallet talk to the node over gRPC on port 26210. The miner
always dials `127.0.0.1:26210` (it has no `--node` flag), so it runs inside
the node's network namespace. The wallet also defaults to
`127.0.0.1:26210`, so run it inside the node container with
`docker exec` (see "Using the wallet" below).

## What each service does

### zethora-node

- Built from the same image as the miner.
- Command: `--testnet --utxoindex`.
- `--utxoindex` keeps the UTXO set indexed, which the wallet needs to
  compute balances.
- Its data directory is a named Docker volume, `zethora-node-data`, so the
  chain survives a `docker-compose down` / `up` cycle.

### zethora-miner

- Command: `--testnet`.
- `network_mode: "service:zethora-node"` puts the miner in the node's
  network namespace. This is required, not cosmetic: the miner source
  hardcodes its node URL to `grpc://127.0.0.1:26210` and it rejects
  unknown flags such as `--node`, so it can only reach the node over
  loopback. Sharing the namespace makes the node's loopback the miner's
  loopback.
- A side effect of sharing the namespace: the miner cannot publish ports of
  its own (it does not need any).
- `depends_on: zethora-node` only controls start order. The node may still
  be loading its database when the miner starts, and the miner exits if its
  first connection attempt fails, so `restart: unless-stopped` keeps
  retrying until the node is ready.
- The miner writes its key file into `/data`, a named Docker volume
  (`zethora-miner-keys`), so the key is not lost when the container is
  recreated.

## Using the wallet

`zethora-wallet` is included in the image but is not part of
`docker-compose up`. Because the miner service uses
`network_mode: "service:zethora-node"`, Compose refuses to `run` that
service, so run the wallet **inside the running node container** with
`docker exec`:

    docker exec -it zethora-node zethora-wallet --testnet

For commands that need the node, the node's own loopback already resolves
to the node, so the default `grpc://127.0.0.1:26210` just works:

    docker exec -it zethora-node zethora-wallet receive --testnet
    docker exec -it zethora-node zethora-wallet sync --testnet
    docker exec -it zethora-node zethora-wallet send <address> <amount> --testnet --dry-run

The wallet looks for its key file in the current directory, which for
`docker exec` is the container's working directory (`/`), not the miner's
`/data` volume. Point it at the miner's key explicitly:

    docker exec -it zethora-node zethora-wallet receive --testnet --key-file /data/zethora-miner-key-testnet.txt

Mount the miner's key volume into the node too if you want the wallet to
read it without a path: add the same `zethora-miner-keys:/data` volume to
the `zethora-node` service, or pass `--key-file` as shown above.

## Running only the node

    docker-compose up -d zethora-node

## Building the image by hand

If you only want the image:

    docker build -t zethora .

Run a one-off node from it:

    docker run --rm -p 16211:16211 -p 26210:26210 zethora --testnet --utxoindex

Anything after the image name is passed to `zethora-node`, because the
image's `ENTRYPOINT` is `zethora-node`.

## Building the Linux binaries

The image expects the binaries to exist already. If `docker build` fails
with a message like

    COPY failed: file not found in build context or excluded by .dockerignore: stat bin/zethora-node: file does not exist

then `bin/zethora-node` is missing. Build the three binaries in release
mode on Linux (or with a Linux cross-compilation toolchain) and place them
in `bin/` using those exact names. On a Windows checkout, make sure the
files have no `.exe` suffix.

## Troubleshooting

**`docker-compose: command not found`**
Older Docker installs ship Compose as a separate binary. Use
`docker compose up -d` (with a space) instead, or install the Compose v2
plugin.

**The miner logs "Connection refused"**
The node is still starting. Check `docker-compose logs zethora-node` and
wait for it to finish loading. The miner exits when its first connection
attempt fails, and `restart: unless-stopped` brings it straight back, so it
reconnects once the node is ready.

**The miner runs but finds no blocks**
Testnet difficulty may be higher than your CPU's hash rate. Leave it
running for a few minutes. On a modern desktop CPU expect roughly 1,000 to
1,500 hashes per second.

**Ports 16211 or 26210 are already in use**
Another node is running on the host. Stop it, or change the host side of
the port mapping in `docker-compose.yml`, for example
`"116211:16211"`.

**`permission denied` when running a binary**
The image sets the executable bit on all three binaries. If you copied your
own binaries in some other way, fix it inside the running container with
`docker exec -it zethora-node chmod +x /usr/local/bin/zethora-node /usr/local/bin/zethora-miner /usr/local/bin/zethora-wallet`.

## Notes on the other Dockerfile

The repository previously shipped a `Dockerfile` that compiled the node
from source with `cargo build --release --bin kaspad`. That file is still
available as `Dockerfile.rust-build`. It is slower and needs the full Rust
toolchain, but it does not require pre-built binaries. The default
`Dockerfile` used by `docker-compose.yml` is the fast, pre-built-binary
image described on this page.
