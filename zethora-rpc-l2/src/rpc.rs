//! The endpoint itself: one axum handler, one dispatcher, the Ethereum methods.
//!
//! The dispatcher is deliberately separate from the HTTP handler. [`handle`] only
//! knows how to read a body and answer with JSON; [`dispatch`] takes a `&[u8]` and
//! returns a [`serde_json::Value`], so the whole protocol can be exercised without
//! a socket, a runtime or a `Router`.
//!
//! Nothing here can panic on client input. Every parameter is checked and turned
//! into a JSON-RPC error, because a handler that panics takes down the connection
//! and, with a `Mutex`, can take the chain state with it.

use alloy_primitives::{Address, B256};
use axum::{Json, body::Bytes, extract::State};
use serde_json::Value;
use zethora_evm::BLOCK_GAS_LIMIT;

use crate::chain::{L2BlockHeader, L2Error, L2Rpc, TransactionReceipt};
use crate::types::{
    INTERNAL_ERROR, JSONRPC_VERSION, RpcError, RpcRequest, RpcResponse, address, data, data_bytes, decode_hex,
    parse_address, quantity, quantity_u64, validate_block_tag,
};

/// The axum handler mounted at [`crate::RPC_PATH`].
///
/// The body is read as raw bytes, not through the `Json` extractor: an extractor
/// rejection is an HTTP-level error with a non-JSON body, and a client like
/// MetaMask reports that as a transport failure. JSON-RPC wants the opposite — a
/// parse failure is an ordinary response carrying error `-32700` — so the body is
/// parsed by [`dispatch`] instead.
pub async fn handle(State(rpc): State<L2Rpc>, body: Bytes) -> Json<Value> {
    Json(dispatch(&rpc, body.as_ref()))
}

/// Answers one JSON-RPC payload, single or batched.
///
/// Batches are answered element by element and in order, and an empty batch is an
/// invalid request rather than an empty reply — a client that sent one would
/// otherwise wait for a response that says nothing.
pub fn dispatch(rpc: &L2Rpc, payload: &[u8]) -> Value {
    let payload: Value = match serde_json::from_slice(payload) {
        Ok(payload) => payload,
        Err(err) => {
            // `id` is `null`: the request could not be read far enough to know it.
            return to_json(RpcResponse::failure(Value::Null, RpcError::parse_error(format!("the body is not JSON: {err}"))));
        }
    };

    match payload {
        Value::Array(batch) => {
            if batch.is_empty() {
                return to_json(RpcResponse::failure(
                    Value::Null,
                    RpcError::invalid_request("an empty batch contains no requests"),
                ));
            }
            Value::Array(batch.into_iter().map(|request| to_json(answer(rpc, request))).collect())
        }
        single => to_json(answer(rpc, single)),
    }
}

/// Answers one request element.
fn answer(rpc: &L2Rpc, request: Value) -> RpcResponse {
    let request: RpcRequest = match serde_json::from_value(request) {
        Ok(request) => request,
        Err(err) => return RpcResponse::failure(Value::Null, RpcError::invalid_request(format!("not a request: {err}"))),
    };

    // The id is echoed even when the call fails: a client matches responses to
    // requests by id, and dropping it on error leaves the caller waiting.
    // Cloned rather than moved: `call` borrows the whole request afterwards.
    let id = normalize_id(request.id.clone());

    if let Some(version) = request.jsonrpc.as_deref() {
        if version != JSONRPC_VERSION {
            return RpcResponse::failure(
                id,
                RpcError::invalid_request(format!("unsupported JSON-RPC version {version:?}: this endpoint speaks 2.0")),
            );
        }
    }

    match call(rpc, &request) {
        Ok(result) => RpcResponse::success(id, result),
        Err(error) => RpcResponse::failure(id, error),
    }
}

/// The id to echo: a string or a number, or `null` for anything else.
///
/// JSON-RPC allows only those two types (plus `null` for notifications). Echoing an
/// object or an array back would put a client's own payload into the response,
/// where it is not expected and may not even be well formed.
fn normalize_id(id: Option<Value>) -> Value {
    match id {
        Some(value @ (Value::String(_) | Value::Number(_))) => value,
        _ => Value::Null,
    }
}

/// Routes a request to its method, or reports that there is no such method.
///
/// The parameters are only parsed inside the arms that take them, so a call to an
/// unimplemented method is answered with `-32601` (the method does not exist) and
/// not with a complaint about parameters that would never have been read.
fn call(rpc: &L2Rpc, request: &RpcRequest) -> Result<Value, RpcError> {
    match request.method.as_str() {
        "eth_chainId" => {
            // A quantity, not a string and not a hash: `0xa28`. MetaMask compares
            // this literally against the chain id the user typed, so the format is
            // part of the contract.
            let chain_id = rpc.with_chain(|chain| chain.chain_id()).map_err(RpcError::internal)?;
            Ok(Value::String(quantity_u64(chain_id)))
        }
        "eth_blockNumber" => {
            let head = rpc.with_chain(|chain| chain.block_number()).map_err(RpcError::internal)?;
            Ok(Value::String(quantity_u64(head)))
        }
        "eth_getBalance" => {
            let params = Params::new(request)?;
            let address = params.address(0)?;
            // The tag is validated but not honoured: see the crate docs. Accepting
            // it is what lets `latest` work without pretending that history exists.
            params.block_tag(1)?;
            let balance = rpc.with_chain(|chain| chain.balance(address)).map_err(RpcError::internal)?;
            Ok(Value::String(quantity(balance)))
        }
        "eth_sendRawTransaction" => {
            let params = Params::new(request)?;
            let raw = params.data(0)?;
            let submitted = rpc
                .with_chain(|chain| chain.submit_raw_transaction(&raw))
                // A poisoned lock is the node's fault, not the caller's.
                .map_err(RpcError::internal)?
                .map_err(transaction_error)?;
            // `data`, not `quantity`: a hash is a byte string and keeps its leading
            // zeros.
            Ok(Value::String(data(submitted.hash)))
        }
        "eth_getTransactionReceipt" => {
            let params = Params::new(request)?;
            let hash = params.hash(0)?;
            let receipt = rpc
                .with_chain(|chain| chain.receipt(hash).cloned())
                .map_err(RpcError::internal)?;
            // `null`, not an error, for a transaction this node does not know: that
            // is the JSON-RPC answer for "not found", and a wallet polls until the
            // receipt appears.
            Ok(receipt.map(|receipt| receipt_object(&receipt)).unwrap_or(Value::Null))
        }
        "eth_estimateGas" => {
            // MetaMask calls this before signing to learn how much gas to attach.
            // The call object is validated for shape but not executed — executing it
            // here would consume the sender's nonce and change state on what is, by
            // contract, a dry run. The honest estimate on a chain with no fee market
            // is the whole block budget, so a real transaction can never run out of
            // a limit it was estimated to need.
            let params = Params::new(request)?;
            params.object(0)?;
            params.block_tag(1)?;
            Ok(Value::String(quantity_u64(BLOCK_GAS_LIMIT)))
        }
        "eth_gasPrice" => {
            // Zero, as a quantity. The L2 has no fee market, so the price of gas is
            // zero and a wallet multiplies any limit by zero to reach a zero fee.
            Ok(Value::String(quantity_u64(0)))
        }
        "eth_getBlockByNumber" => {
            let params = Params::new(request)?;
            let tag = params.optional_string(0)?;
            // `full_transactions` is read only so a malformed flag is still a clean
            // `-32602`; the node cannot honour it, see `block_object`.
            let full = params.bool(1)?;
            let number = resolve_block(rpc, tag)?;
            let header = rpc.with_chain(|chain| chain.block(number).cloned()).map_err(RpcError::internal)?;
            Ok(header.map(|header| block_object(&header, full)).unwrap_or(Value::Null))
        }
        "net_version" => {
            // A decimal string, not a hex quantity: MetaMask compares this against
            // the network it believes it is talking to, and `0xa28` is not `2600`.
            let chain_id = rpc.with_chain(|chain| chain.chain_id()).map_err(RpcError::internal)?;
            Ok(Value::String(chain_id.to_string()))
        }
        "web3_clientVersion" => {
            // A stable identifier. MetaMask only prints it; nothing parses it.
            Ok(Value::String(format!("zethora-rpc-l2/v{}", env!("CARGO_PKG_VERSION"))))
        }
        other => Err(RpcError::method_not_found(other)),
    }
}

/// Maps a chain-level refusal onto the JSON-RPC error a client sees.
fn transaction_error(error: L2Error) -> RpcError {
    match error {
        L2Error::InvalidTransaction(reason) => RpcError::invalid_params(format!("the transaction cannot be decoded: {reason}")),
        L2Error::Rejected(reason) => RpcError::server(format!("the transaction was rejected: {reason}")),
    }
}

/// Resolves a block identifier to a block number.
///
/// `latest`, `pending`, `safe` and `finalized` all name the head: this chain has
/// instant finality, so there is no block that is mined but not yet final.
/// `earliest` is genesis. A `0x`-prefixed number is the height itself.
fn resolve_block(rpc: &L2Rpc, tag: Option<&str>) -> Result<u64, RpcError> {
    let head = rpc.with_chain(|chain| chain.block_number()).map_err(RpcError::internal)?;
    match tag {
        None | Some("latest") | Some("pending") | Some("safe") | Some("finalized") => Ok(head),
        Some("earliest") => Ok(0),
        Some(numbered) if numbered.starts_with("0x") || numbered.starts_with("0X") => {
            u64::from_str_radix(&numbered[2..], 16)
                .map_err(|_| RpcError::invalid_params(format!("block number {numbered:?} is not a hex number")))
        }
        Some(other) => Err(RpcError::invalid_params(format!(
            "unknown block tag {other:?}: expected latest, earliest, pending, safe, finalized, or a hex block number"
        ))),
    }
}

/// A JSON-RPC block object for `eth_getBlockByNumber`.
///
/// The fields this node cannot know — proof-of-work difficulty, uncles, a real
/// bloom — are answered as zero or empty, which is what a client needs to render
/// the block without inventing data. `full_transactions` is accepted but cannot be
/// honoured: this node remembers only the transaction hashes, not the transactions
/// themselves, so hashes are returned in both cases.
fn block_object(header: &L2BlockHeader, _full_transactions: bool) -> Value {
    let transactions: Vec<Value> =
        header.transactions.iter().map(|hash| Value::String(data(*hash))).collect();
    serde_json::json!({
        "number": quantity_u64(header.number),
        "hash": data(header.hash),
        "parentHash": data(header.parent_hash),
        "nonce": "0x0000000000000000",
        "sha3Uncles": data(B256::ZERO),
        "logsBloom": zero_bloom(),
        "transactionsRoot": data(B256::ZERO),
        "stateRoot": data(header.state_root),
        "receiptsRoot": data(B256::ZERO),
        "miner": address(Address::ZERO),
        "difficulty": "0x0",
        "totalDifficulty": "0x0",
        "extraData": "0x",
        "size": quantity_u64(0),
        "gasLimit": quantity_u64(BLOCK_GAS_LIMIT),
        "gasUsed": quantity_u64(header.gas_used),
        "timestamp": quantity_u64(header.timestamp),
        "transactions": transactions,
        "uncles": [],
    })
}

/// A JSON-RPC receipt object for `eth_getTransactionReceipt`.
fn receipt_object(receipt: &TransactionReceipt) -> Value {
    serde_json::json!({
        "transactionHash": data(receipt.hash),
        "transactionIndex": quantity_u64(receipt.transaction_index),
        "blockHash": data(receipt.block_hash),
        "blockNumber": quantity_u64(receipt.block_number),
        "from": address(receipt.from),
        "to": receipt.to.map(address),
        "cumulativeGasUsed": quantity_u64(receipt.cumulative_gas_used),
        "gasUsed": quantity_u64(receipt.gas_used),
        "contractAddress": receipt.contract_address.map(address),
        "logs": [],
        "logsBloom": zero_bloom(),
        "status": if receipt.success { "0x1" } else { "0x0" },
        "type": quantity_u64(u64::from(receipt.transaction_type)),
    })
}

/// The 256-byte all-zero logs bloom this node always reports.
fn zero_bloom() -> String {
    data_bytes(&[0u8; 256])
}

/// Serialises a response, or a protocol-level error if that were ever impossible.
fn to_json(response: RpcResponse) -> Value {
    match serde_json::to_value(&response) {
        Ok(value) => value,
        // Unreachable in practice: every field is a string, an integer or a JSON
        // value. The fallback exists so that this function cannot panic.
        Err(err) => serde_json::json!({
            "jsonrpc": JSONRPC_VERSION,
            "id": Value::Null,
            "error": { "code": INTERNAL_ERROR, "message": format!("the response could not be encoded: {err}") },
        }),
    }
}

/// The positional parameters of one request.
///
/// This is where a request stops being trusted: an index that was not supplied, a
/// value of the wrong type, and a string that is not the hex or the tag it claims
/// to be are all turned into `-32602` before any of them reaches the chain.
struct Params<'a> {
    method: &'a str,
    values: &'a [Value],
}

impl<'a> Params<'a> {
    /// Reads the parameter array of `request`.
    fn new(request: &'a RpcRequest) -> Result<Self, RpcError> {
        let values: &'a [Value] = match request.params.as_ref() {
            // A method that takes no parameters is regularly called with `params`
            // omitted, with `null`, or with an empty array. All three mean the same
            // thing here.
            None | Some(Value::Null) => &[],
            Some(Value::Array(values)) => values.as_slice(),
            Some(_) => {
                return Err(RpcError::invalid_params(format!(
                    "{} takes positional parameters, so params must be an array",
                    request.method
                )));
            }
        };
        Ok(Self { method: request.method.as_str(), values })
    }

    /// The parameter at `index`, which must be present.
    fn value(&self, index: usize) -> Result<&'a Value, RpcError> {
        self.values
            .get(index)
            .ok_or_else(|| RpcError::invalid_params(format!("{} requires parameter {index}", self.method)))
    }

    /// The parameter at `index`, which must be a string.
    fn string(&self, index: usize) -> Result<&'a str, RpcError> {
        match self.value(index)? {
            Value::String(value) => Ok(value.as_str()),
            other => Err(RpcError::invalid_params(format!(
                "parameter {index} of {} must be a string, got {other}",
                self.method
            ))),
        }
    }

    /// The parameter at `index`, which must be a 20-byte hex address.
    fn address(&self, index: usize) -> Result<Address, RpcError> {
        let raw = self.string(index)?;
        parse_address(raw).map_err(|reason| RpcError::invalid_params(format!("parameter {index} of {}: {reason}", self.method)))
    }

    /// The parameter at `index`, which must be a hex byte string.
    fn data(&self, index: usize) -> Result<Vec<u8>, RpcError> {
        let raw = self.string(index)?;
        decode_hex(raw)
            .map_err(|reason| RpcError::invalid_params(format!("parameter {index} of {} is not hex: {reason}", self.method)))
    }

    /// The optional parameter at `index`, which must be a string when present.
    fn optional_string(&self, index: usize) -> Result<Option<&'a str>, RpcError> {
        match self.values.get(index) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) => Ok(Some(value.as_str())),
            Some(other) => Err(RpcError::invalid_params(format!(
                "parameter {index} of {} must be a string, got {other}",
                self.method
            ))),
        }
    }

    /// The optional parameter at `index`, which must be a boolean when present.
    fn bool(&self, index: usize) -> Result<bool, RpcError> {
        match self.values.get(index) {
            None | Some(Value::Null) => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            Some(other) => Err(RpcError::invalid_params(format!(
                "parameter {index} of {} must be a boolean, got {other}",
                self.method
            ))),
        }
    }

    /// The parameter at `index`, which must be a JSON object (a transaction call).
    fn object(&self, index: usize) -> Result<(), RpcError> {
        match self.value(index)? {
            Value::Object(_) => Ok(()),
            other => Err(RpcError::invalid_params(format!(
                "parameter {index} of {} must be a transaction call object, got {other}",
                self.method
            ))),
        }
    }

    /// The parameter at `index`, which must be a 32-byte hex hash.
    fn hash(&self, index: usize) -> Result<B256, RpcError> {
        let raw = self.string(index)?;
        let bytes = decode_hex(raw)
            .map_err(|reason| RpcError::invalid_params(format!("parameter {index} of {} is not hex: {reason}", self.method)))?;
        if bytes.len() != 32 {
            return Err(RpcError::invalid_params(format!(
                "parameter {index} of {} must be a 32-byte hash, got {} bytes",
                self.method,
                bytes.len()
            )));
        }
        Ok(B256::from_slice(&bytes))
    }

    /// The optional parameter at `index`, which must be a block tag or number.
    fn block_tag(&self, index: usize) -> Result<(), RpcError> {
        match self.values.get(index) {
            None | Some(Value::Null) => Ok(()),
            Some(Value::String(tag)) => validate_block_tag(tag)
                .map_err(|reason| RpcError::invalid_params(format!("parameter {index} of {}: {reason}", self.method))),
            Some(other) => Err(RpcError::invalid_params(format!(
                "parameter {index} of {} must be a block tag or a hex block number, got {other}",
                self.method
            ))),
        }
    }
}
