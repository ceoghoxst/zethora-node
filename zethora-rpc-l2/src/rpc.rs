//! The endpoint itself: one axum handler, one dispatcher, four methods.
//!
//! The dispatcher is deliberately separate from the HTTP handler. [`handle`] only
//! knows how to read a body and answer with JSON; [`dispatch`] takes a `&[u8]` and
//! returns a [`serde_json::Value`], so the whole protocol can be exercised without
//! a socket, a runtime or a `Router`.
//!
//! Nothing here can panic on client input. Every parameter is checked and turned
//! into a JSON-RPC error, because a handler that panics takes down the connection
//! and, with a `Mutex`, can take the chain state with it.

use alloy_primitives::Address;
use axum::{Json, body::Bytes, extract::State};
use serde_json::Value;

use crate::chain::{L2Error, L2Rpc};
use crate::types::{
    INTERNAL_ERROR, JSONRPC_VERSION, RpcError, RpcRequest, RpcResponse, data, decode_hex, parse_address, quantity,
    quantity_u64, validate_block_tag,
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
