# zethora-rpc-l2

The JSON-RPC door into the Zethora L2: an `axum` server that exposes the
[`zethora-evm`](../zethora-evm) executor over the standard Ethereum methods, so a
wallet or a tool that already speaks Ethereum can talk to Zethora without a
bespoke client.

```
cargo run -p zethora-rpc-l2
# zethora-rpc-l2: JSON-RPC listening on http://0.0.0.0:8545
```

## Methods

| Method | Answer |
| --- | --- |
| `eth_chainId` | `0xa28` (2600) |
| `eth_blockNumber` | number of the newest sealed block |
| `eth_getBalance(address, tag)` | balance in wei |
| `eth_sendRawTransaction(raw)` | hash of a transaction that is already in a block |

Batches are supported, every request is answered with HTTP 200 (a failure is a
JSON-RPC `error` object), and `CorsLayer::permissive()` lets a browser page call
the endpoint. Any other method answers `-32601`.

## Talking to it

```bash
curl -s -X POST http://localhost:8545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}'
# {"jsonrpc":"2.0","id":1,"result":"0xa28"}
```

```bash
curl -s -X POST http://localhost:8545 \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"eth_getBalance","params":["0x0000000000000000000000000000000000000000","latest"]}'
```

In MetaMask: **Add network → Add a network manually**, RPC URL
`http://localhost:8545`, chain id `2600`, currency `ZTHR`.

## What it is not

There is no chain database behind this endpoint. State is one in-memory
`EvmExecutor` plus the head block number, each accepted transaction executes
immediately and seals one block, and the state is gone when the process exits.
So there is no history (`eth_getBalance` answers for *current* state whatever tag
it is asked about), no mempool, and no `eth_getBlockByNumber`. That boundary is
the point of this crate: it is the sequencing-free wrapper that lets tooling talk
to the engine, not a node.

## Tests

```
cargo test -p zethora-rpc-l2
```

`tests/eth_chain_id.rs` drives the production router with the same tower
`Service` call `axum::serve` makes per request, and asserts that `eth_chainId`
returns `0xa28` and that the CORS header is present.

`tests/doomsday_rpc.rs` is the adversarial half: a ten-thousand-level JSON
nesting bomb, a ten megabyte body, malformed `eth_sendRawTransaction` calldata
(including a gas limit of `u64::MAX` and one of 2^256-1), an empty batch, a
ten-thousand-request batch, unknown methods and wrongly typed parameters. Each
attack has to end in the JSON-RPC error the specification names — `-32700`,
`-32600`, `-32601`, `-32602` or `-32000`, never a 5xx or a panic — and every test
finishes by asking `eth_chainId` again, because a panic in a handler poisons the
chain mutex and the endpoint would answer `-32603` for the life of the process
while still looking alive.
