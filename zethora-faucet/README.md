# Zethora Testnet Faucet

A one-page faucet for the Zethora public testnet. Paste a `zethoratest:` address, press **Claim 1 ZTHR**, and the
faucet sends exactly 1 ZTHR from its own wallet and shows the transaction id.

Testnet coins are worth zero. There is no presale, no airdrop and no promise of value.

## What is in this folder

| File | What it is |
| --- | --- |
| `src/main.rs` | The backend: `axum` on port 8080, `POST /claim`, address check, one `zethora-wallet send` per claim |
| `index.html` | The page: dark mode in the same colours and fonts as the Zethora website (`site/index.html`) |
| `faucet.js` | The page's script: validates the address, calls `/claim`, shows success with the TxID or the error |
| `Cargo.toml` | This crate. It has its own empty `[workspace]`, so the Zethora workspace is never involved |

This folder is **not** a member of the Zethora workspace and does not touch the node's `Cargo.toml`. It shells out to
`zethora-wallet.exe` exactly the way a user would, so it needs no Zethora crates to build.

## What it needs

1. A synced testnet node:
   `cargo run --release --bin kaspad -- --testnet --utxoindex`
   (`--utxoindex` is required: `send` asks the node which coins the faucet address holds.)
2. The wallet built: `cargo build --release -p zethora-wallet` (or a released `zethora-wallet.exe`).
3. A funded faucet key: a file with 64 hex characters, the same format `zethora-miner --testnet` writes to
   `zethora-miner-key-testnet.txt`. **Use a key that holds only testnet coins you are happy to give away.**

## Run it

From the repository root (so the default wallet and key paths are found):

```powershell
cargo run --release --manifest-path zethora-faucet/Cargo.toml
```

Then open <http://127.0.0.1:8080>.

The console prints the page address, the wallet, the key file and the node it will use. If the wallet or the key file is
missing it stops immediately with a one-line reason instead of failing on the first visitor.

Running from this folder works too: `cargo run --release`.

### Configuration (environment variables)

| Variable | Default | Meaning |
| --- | --- | --- |
| `ZETHORA_WALLET` | `zethora-wallet.exe` | The wallet executable the faucet runs |
| `ZETHORA_FAUCET_KEY_FILE` | `zethora-miner-key-testnet.txt` | The key the faucet pays from |
| `ZETHORA_FAUCET_NODE` | the wallet's default, `grpc://127.0.0.1:26210` | The node the wallet talks to (`--node`) |
| `ZETHORA_FAUCET_ADDR` | `127.0.0.1` | Listen address. Set `0.0.0.0` to accept connections from other machines - only do that behind a reverse proxy or firewall, the faucet has no login |

Example with the release binary and a separate faucet key:

```powershell
$env:ZETHORA_WALLET = ".\target\release\zethora-wallet.exe"
$env:ZETHORA_FAUCET_KEY_FILE = "C:\zethora-faucet-key.txt"
cargo run --release --manifest-path zethora-faucet/Cargo.toml
```

## The API

`POST /claim` with a JSON body:

```json
{ "address": "zethoratest:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqa8acjxhw" }
```

Success - `200 OK`:

```json
{ "success": true, "txid": "<transaction id>", "message": "Sent 1.0 ZTHR to zethoratest:...", "amount": "1.0" }
```

Failure - the body keeps the same shape so the page has one thing to read:

```json
{ "success": false, "message": "That is not a Zethora testnet address: it has to start with zethoratest:", "amount": "1.0" }
```

| Status | When |
| --- | --- |
| 200 | Coins sent, `txid` is the transaction id |
| 400 | The body is not JSON `{ "address": ... }`, or the address is not a `zethoratest:` address |
| 429 | That address already claimed within the last hour (`retry_after_seconds` says how long) |
| 502 | The wallet refused the payment (no spendable coins, node not reachable, bad checksum) - `message` is the wallet's own reason |

## How a claim works

1. The address is checked for shape (`zethoratest:` plus the bech32 payload, same rule as the Windows app) before
   anything is sent. The wallet then checks the real checksum, and its answer is the one that counts.
2. Claims run one at a time: two `send` calls at once would race for the same coins.
3. The faucet runs
   `zethora-wallet send <address> 1.0 --testnet --key-file <key> [--node <url>]`
   and reads the transaction id from the `Sent. Transaction id: ...` line. Arguments are passed as a list, never
   through a shell, so an address can never turn into a command.
4. A wallet run that takes longer than 2 minutes is killed and reported as a failure.
5. After a successful send the address is on a 1-hour cooldown. The table lives in memory, so restarting the faucet
   clears it.

## Tests

```powershell
cargo test --manifest-path zethora-faucet/Cargo.toml
```

The tests cover the address check, the transaction-id parsing, the wallet-refusal message, the cooldown and the key
file check. They never start the wallet or talk to a node.

## Limits worth knowing

- No captcha and no login: the cooldown is per address, not per person. Fund the faucet key with testnet coins you can
  afford to lose, and put it behind a proxy with rate limits if you expose it publicly.
- The cooldown is in memory, so a restart resets it, and on a multi-process deployment each process has its own table.
- The wallet takes 10 seconds or so per claim (it reads the chain and signs), so claims queue behind each other.
