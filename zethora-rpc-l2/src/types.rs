//! The JSON-RPC 2.0 wire format, the error codes Ethereum clients expect, and
//! the hex helpers both are built from.
//!
//! The three encodings a client distinguishes are kept separate on purpose,
//! because mixing them up is the classic way to break a wallet:
//!
//! * **quantity** — a number, `0x`-prefixed, with no leading zeros (`0x0` for
//!   zero). `eth_chainId` and `eth_getBalance` answer with this.
//! * **data** — an uninterpreted byte string, `0x`-prefixed, zero-padded to its
//!   full width. `eth_sendRawTransaction` answers with a 32-byte hash in this
//!   form.
//! * **string** — plain text, no prefix.
//!
//! Every helper here is hand-written rather than delegated, so the exact bytes on
//! the wire are visible in this file and cannot change under a dependency bump.

use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The only protocol version this endpoint speaks.
pub const JSONRPC_VERSION: &str = "2.0";

/// The body could not be parsed as JSON.
pub const PARSE_ERROR: i32 = -32700;
/// The JSON parsed but is not a JSON-RPC request.
pub const INVALID_REQUEST: i32 = -32600;
/// The method is not implemented by this endpoint.
pub const METHOD_NOT_FOUND: i32 = -32601;
/// The parameters are malformed, missing, or name something invalid.
pub const INVALID_PARAMS: i32 = -32602;
/// The server failed for a reason of its own.
pub const INTERNAL_ERROR: i32 = -32603;
/// Start of the range JSON-RPC reserves for implementation-defined errors.
///
/// Ethereum nodes use it for "the request was well formed but the node refuses
/// it": a transaction the EVM would not include is the canonical case.
pub const SERVER_ERROR: i32 = -32000;

/// The number of bytes in an EVM address.
const ADDRESS_BYTES: usize = 20;

/// One JSON-RPC request.
///
/// `jsonrpc`, `id` and `params` are all optional in the wire format described
/// here because clients disagree about which of them to send; `method` is not,
/// and a body without one is rejected as an invalid request.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct RpcRequest {
    /// Protocol version. Accepted when absent (some clients omit it), rejected
    /// when present and not [`JSONRPC_VERSION`].
    #[serde(default)]
    pub jsonrpc: Option<String>,
    /// Correlation id, echoed back verbatim. A request without one gets `null`,
    /// which is what JSON-RPC prescribes for notifications.
    #[serde(default)]
    pub id: Option<Value>,
    /// The method to call.
    pub method: String,
    /// Positional parameters. A named-parameter object is rejected: every
    /// Ethereum method this endpoint implements takes positional parameters, and
    /// guessing at an object's field names would be inventing an interface no
    /// client uses.
    #[serde(default)]
    pub params: Option<Value>,
}

/// One JSON-RPC response.
///
/// Exactly one of `result` and `error` is present on the wire; the other is
/// omitted rather than sent as `null`, because a client that trusts the presence
/// of `result` would otherwise accept a failure.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RpcResponse {
    /// Always [`JSONRPC_VERSION`].
    pub jsonrpc: &'static str,
    /// Echo of the request id, or `null` when it could not be determined.
    pub id: Value,
    /// The successful result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// The failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl RpcResponse {
    /// A response carrying `result`.
    pub fn success(id: Value, result: Value) -> Self {
        Self { jsonrpc: JSONRPC_VERSION, id, result: Some(result), error: None }
    }

    /// A response carrying `error`.
    pub fn failure(id: Value, error: RpcError) -> Self {
        Self { jsonrpc: JSONRPC_VERSION, id, result: None, error: Some(error) }
    }
}

/// A JSON-RPC error object.
///
/// The message describes what was wrong with the request. It never echoes a blob
/// of the caller's own input back: a client that merely forwarded a stack trace
/// to a log would be handing untrusted bytes to whatever reads that log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RpcError {
    /// Numeric code, one of the constants in this module.
    pub code: i32,
    /// Human-readable description.
    pub message: String,
}

impl RpcError {
    /// An error with an explicit code.
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    /// The body is not JSON ([`PARSE_ERROR`]).
    pub fn parse_error(message: impl Into<String>) -> Self {
        Self::new(PARSE_ERROR, message)
    }

    /// The body is JSON but not a request ([`INVALID_REQUEST`]).
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(INVALID_REQUEST, message)
    }

    /// The method is not implemented ([`METHOD_NOT_FOUND`]).
    pub fn method_not_found(method: &str) -> Self {
        Self::new(METHOD_NOT_FOUND, format!("the method {method} is not implemented by this endpoint"))
    }

    /// The parameters are unusable ([`INVALID_PARAMS`]).
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, message)
    }

    /// The server failed for its own reasons ([`INTERNAL_ERROR`]).
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(INTERNAL_ERROR, message)
    }

    /// The request was well formed but the node refused it ([`SERVER_ERROR`]).
    pub fn server(message: impl Into<String>) -> Self {
        Self::new(SERVER_ERROR, message)
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} (JSON-RPC code {})", self.message, self.code)
    }
}

impl std::error::Error for RpcError {}

/// Encodes `bytes` as lowercase hex, without the `0x` prefix.
pub fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        // Both nibbles index `DIGITS` in `0..16`, so neither lookup can miss and
        // no byte is ever dropped from the encoding.
        encoded.push(char::from(*DIGITS.get(usize::from(byte >> 4)).unwrap_or(&b'0')));
        encoded.push(char::from(*DIGITS.get(usize::from(byte & 0x0f)).unwrap_or(&b'0')));
    }
    encoded
}

/// Decodes a `0x`-prefixed (or bare) hex string into bytes.
///
/// The prefix is optional because block numbers arrive as bare hex from some
/// clients, and because a `data` parameter that lost its prefix should still be
/// readable. A string with an odd number of digits is an error rather than a
/// guess: `0xf` could mean `0x0f` or `0xf0`, and half a byte is not data.
pub fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let digits = input.strip_prefix("0x").or_else(|| input.strip_prefix("0X")).unwrap_or(input);
    let pairs = digits.as_bytes();
    if pairs.len() % 2 != 0 {
        return Err(format!("hex string has an odd number of digits ({})", pairs.len()));
    }

    let mut decoded = Vec::with_capacity(pairs.len() / 2);
    for pair in pairs.chunks_exact(2) {
        // `chunks_exact(2)` yields exactly two bytes and the odd-length case was
        // rejected above, so neither index can be out of bounds.
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

/// The value of one hex digit.
fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(format!("invalid hex character {:?}", char::from(other))),
    }
}

/// Formats a 256-bit value as a JSON-RPC **quantity**.
///
/// Leading zero bytes *and* the leading zero nibble of the first significant byte
/// are both dropped: `1` is `0x1`, never `0x01`, because a client comparing the
/// string it was told to expect (`0xa28` for chain 2600) would fail otherwise.
pub fn quantity(value: U256) -> String {
    let encoded = encode_hex(&value.to_be_bytes::<32>());
    let significant = encoded.trim_start_matches('0');
    if significant.is_empty() {
        // The value was zero; `0x` on its own is not a number.
        "0x0".to_string()
    } else {
        format!("0x{significant}")
    }
}

/// Formats a `u64` as a JSON-RPC **quantity**.
pub fn quantity_u64(value: u64) -> String {
    format!("0x{value:x}")
}

/// Formats a 32-byte value as JSON-RPC **data**: `0x` plus all 64 digits.
///
/// A transaction hash is a byte string, not a number, so it keeps its leading
/// zeros. Trimming them, as [`quantity`] does, would produce a value no client
/// could look up.
pub fn data(bytes: B256) -> String {
    format!("0x{}", encode_hex(bytes.as_slice()))
}

/// Parses a 20-byte address from a `0x`-prefixed hex string.
///
/// The length is checked before the address is built, so a short or long string
/// is a clean error instead of a panic or a silently truncated address.
pub fn parse_address(input: &str) -> Result<Address, String> {
    let raw = decode_hex(input)?;
    if raw.len() != ADDRESS_BYTES {
        return Err(format!("an address is {ADDRESS_BYTES} bytes, got {}", raw.len()));
    }
    Ok(Address::from_slice(&raw))
}

/// Checks that `tag` is a block identifier this endpoint can be asked about.
///
/// Only the *shape* is validated: the endpoint holds no history, so every tag is
/// answered from current state. Rejecting a tag that is neither a known keyword
/// nor a hex number still matters, because silently ignoring a parameter teaches
/// a client that the parameter works.
pub fn validate_block_tag(tag: &str) -> Result<(), String> {
    match tag {
        "latest" | "earliest" | "pending" | "safe" | "finalized" => Ok(()),
        numbered if numbered.starts_with("0x") || numbered.starts_with("0X") => {
            decode_hex(numbered).map(|_| ())?;
            Ok(())
        }
        other => Err(format!(
            "unknown block tag {other:?}: expected latest, earliest, pending, safe, finalized, or a hex block number"
        )),
    }
}
