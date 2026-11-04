use super::{
    TransactionValidator,
    errors::{TxResult, TxRuleError},
};
use crate::constants::{MAX_ZETS, TX_VERSION_TOCCATA};
use kaspa_consensus_core::subnets::{
    CoinbaseSubnetwork, NativeSubnetwork, SUBNETWORK_NAMESPACE_LEN, SUBNETWORK_ZERO_TAIL_LEN, Subnetwork,
};
use kaspa_consensus_core::tx::Transaction;
use std::collections::HashSet;

impl TransactionValidator {
    /// Performs a variety of transaction validation checks which are independent of any
    /// context -- header or utxo. **Note** that any check performed here should be moved to
    /// header contextual validation if it becomes HF activation dependent. This is bcs we rely
    /// on checks here to be truly independent and avoid calling it multiple times wherever possible
    /// (e.g., BBT relies on mempool in isolation checks even though virtual daa score might have changed)   
    pub fn validate_tx_in_isolation(&self, tx: &Transaction) -> TxResult<()> {
        self.check_transaction_inputs_in_isolation(tx)?;
        self.check_transaction_outputs_in_isolation(tx)?;
        self.check_coinbase_in_isolation(tx)?;

        check_transaction_output_value_ranges(tx)?;
        check_duplicate_transaction_inputs(tx)?;
        check_gas(tx)?;
        check_transaction_subnetwork(tx)?;
        check_transaction_version(tx)?;
        check_tx_version_specific_fields(tx)?;
        check_private_payment(tx, self.private_spends_enabled, &self.zethora_genesis())
    }

    fn check_transaction_inputs_in_isolation(&self, tx: &Transaction) -> TxResult<()> {
        self.check_transaction_inputs_count(tx)?;
        self.check_transaction_signature_scripts(tx)
    }

    fn check_transaction_outputs_in_isolation(&self, tx: &Transaction) -> TxResult<()> {
        self.check_transaction_outputs_count(tx)?;
        self.check_transaction_script_public_keys(tx)
    }

    fn check_coinbase_in_isolation(&self, tx: &Transaction) -> TxResult<()> {
        if !tx.is_coinbase() {
            return Ok(());
        }
        if !tx.inputs.is_empty() {
            return Err(TxRuleError::CoinbaseHasInputs(tx.inputs.len()));
        }

        if tx.storage_mass() > 0 {
            return Err(TxRuleError::CoinbaseNonZeroMassCommitment);
        }

        let outputs_limit = self.ghostdag_k as u64 + 2;
        if tx.outputs.len() as u64 > outputs_limit {
            return Err(TxRuleError::CoinbaseTooManyOutputs(tx.outputs.len(), outputs_limit));
        }

        for (i, output) in tx.outputs.iter().enumerate() {
            if output.script_public_key.script().len() > self.coinbase_payload_script_public_key_max_len as usize {
                return Err(TxRuleError::CoinbaseScriptPublicKeyTooLong(i));
            }
        }
        Ok(())
    }

    fn check_transaction_outputs_count(&self, tx: &Transaction) -> TxResult<()> {
        if tx.is_coinbase() {
            // We already check coinbase outputs count vs. Ghostdag K + 2
            return Ok(());
        }
        if tx.outputs.len() > self.max_tx_outputs {
            return Err(TxRuleError::TooManyOutputs(tx.outputs.len(), self.max_tx_outputs));
        }

        Ok(())
    }

    fn check_transaction_inputs_count(&self, tx: &Transaction) -> TxResult<()> {
        // Zethora: a fully private payment pays its fee from private coins and needs no visible input (ZTH-SPEC-006 §9).
        // Its spends are checked like any other private payment: proof, unspent coin tags, matured coin list snapshot.
        if !tx.is_coinbase() && tx.inputs.is_empty() && !kaspa_consensus_core::zethora_private::pays_from_private_pool(&tx.payload) {
            return Err(TxRuleError::NoTxInputs);
        }
        // With no inputs there are no sequence numbers, so a lock time could never be enforced: require none at all.
        if !tx.is_coinbase() && tx.inputs.is_empty() && tx.lock_time != 0 {
            return Err(TxRuleError::InvalidPrivatePayment("a payment with no visible coin must have lock time 0".to_string()));
        }

        if tx.inputs.len() > self.max_tx_inputs {
            return Err(TxRuleError::TooManyInputs(tx.inputs.len(), self.max_tx_inputs));
        }

        Ok(())
    }

    // The main purpose of this check is to avoid overflows when calculating transaction mass later.
    fn check_transaction_signature_scripts(&self, tx: &Transaction) -> TxResult<()> {
        let max_signature_script_len = self.max_signature_script_len;
        if let Some(i) = tx.inputs.iter().position(|input| input.signature_script.len() > max_signature_script_len) {
            return Err(TxRuleError::TooBigSignatureScript(i, max_signature_script_len));
        }

        Ok(())
    }

    // The main purpose of this check is to avoid overflows when calculating transaction mass later.
    fn check_transaction_script_public_keys(&self, tx: &Transaction) -> TxResult<()> {
        if let Some(i) = tx.outputs.iter().position(|out| out.script_public_key.script().len() > self.max_script_public_key_len) {
            return Err(TxRuleError::TooBigScriptPublicKey(i, self.max_script_public_key_len));
        }

        Ok(())
    }
}

fn check_duplicate_transaction_inputs(tx: &Transaction) -> TxResult<()> {
    let mut existing = HashSet::new();
    for input in &tx.inputs {
        if !existing.insert(input.previous_outpoint) {
            return Err(TxRuleError::TxDuplicateInputs);
        }
    }
    Ok(())
}

const ZEROES_19: &[u8; 19] = &[0; 19];

/// Zethora: the verifying key for private payment proofs, built once (about a second) on first use.
///
/// The key is built on a separate plain thread: building uses rayon internally, and validation itself runs on
/// rayon workers, so building it directly here could let a worker re-enter this initialisation and hang.
fn private_payment_verifying_key() -> &'static zethora_shielded::orchard::circuit::VerifyingKey {
    static VK: std::sync::OnceLock<zethora_shielded::orchard::circuit::VerifyingKey> = std::sync::OnceLock::new();
    VK.get_or_init(|| {
        std::thread::spawn(|| zethora_shielded::orchard::circuit::VerifyingKey::build(zethora_shielded::CIRCUIT))
            .join()
            .expect("building the private payment verifying key")
    })
}

/// Zethora (ZTH-SPEC-006): a transaction whose payload carries a private payment must hold a well-formed
/// payment whose signatures and proof check out, bound to this exact transaction.
///
/// Emergency switch (§7.3), level (a): when `spends_enabled` is false (testnet and mainnet until an outside audit),
/// NO private payment is accepted (no shielding, no spend, no unshield). The refusal fires before decode and proof, so no proof work is spent on testnet. When it is true (devnet, simnet), spends are allowed here and their
/// chain rules are checked in UTXO context: every coin tag unspent (§6.3) and the anchor a matured snapshot of the
/// chain's own coin list (§6.2), which is what keeps a spend from pointing at a made-up coin list.
///
/// A coinbase is never itself a private payment (its payload is the supply ledger and coin list seal, read through
/// `zethora_private::private_payload`, which returns nothing for a coinbase). It can only ask for a reward to go to a
/// private address, with the miner tag `SHD1 | pool version | Orchard address` (ZTH-SPEC-006 §7.4). That is a private
/// payment the node would have to make on the miner's behalf, so when the switch is off it is refused exactly like
/// one, before any other work. When the switch is on the tag is accepted: paying it out is not implemented yet, so
/// the reward still goes to the transparent script the miner named.
fn check_private_payment(tx: &Transaction, spends_enabled: bool, genesis_hash: &kaspa_hashes::Hash) -> TxResult<()> {
    if tx.is_coinbase() {
        return check_coinbase_shielded_tag(tx, spends_enabled);
    }
    let Some(encoded) =
        kaspa_consensus_core::zethora_private::private_payment_bytes(kaspa_consensus_core::zethora_private::private_payload(tx))
    else {
        return Ok(());
    };
    let invalid = TxRuleError::InvalidPrivatePayment;
    // Fails its own proof or signatures: no honest node relays these, so the sending peer gets banned (ZTH-SPEC-006
    // §8.3). Format errors stay plain refusals: they are cheap to catch, and after a future pool upgrade an honest
    // newer node could send a format an older node can't read yet.
    let forged = TxRuleError::InvalidPrivatePaymentProof;
    if !tx.subnetwork_id.is_native() {
        return Err(invalid("private payments must use the native subnetwork".to_string()));
    }
    // G11 (§7.3 level (a)): on testnet and mainnet, refuse every private payment
    // before decode and proof. Plain refusal, not a proof error, so no peer is
    // banned for it. This closes the one-way trap where a user could shield but
    // never withdraw.
    if !spends_enabled {
        return Err(invalid("private payments are disabled on this network (ZTH-SPEC-006 §7.3)".to_string()));
    }
    let (bundle, _pool) = zethora_shielded::codec::decode(encoded).map_err(|e| invalid(e.to_string()))?;
    // No spent-coin tag may appear twice inside one payment (ZTH-SPEC-006 §6.3)
    let mut seen = std::collections::HashSet::new();
    if !bundle.actions().iter().all(|a| seen.insert(a.nullifier().to_bytes())) {
        return Err(forged("the same private coin tag appears twice in one payment".to_string()));
    }
    let digest = kaspa_consensus_core::hashing::tx::zethora_private_payment_digest(tx, genesis_hash);
    zethora_shielded::verify_payment(&bundle, private_payment_verifying_key(), &digest.as_bytes()).map_err(|e| match e {
        // Not proof of forgery (seam review pack 1, #7): refuse without banning
        zethora_shielded::VerifyError::Commitment => invalid(format!("{e:?}")),
        _ => forged(format!("{e:?}")),
    })
}

/// First four bytes of the miner tag a coinbase carries when the miner wants its reward paid to a private address.
/// `zethora-miner` writes `SHD1 | pool version | Orchard address` as its extra data (ZTH-SPEC-006 §7.4); the node
/// side of that agreement lives here, in consensus.
const SHIELDED_TAG_PREFIX: [u8; 4] = *b"SHD1";

/// Where the miner tag starts in a coinbase payload: after the supply ledger, the coin list root, the private state
/// fingerprint, the script public key version and length, and the script public key itself
/// (`CoinbaseManager::serialize_coinbase_payload`). Read from the lengths rather than a constant, so a change to any of
/// them can never make this silently read the wrong window.
///
/// The length byte is *checked*, not trusted. The payload is written by the miner, so a hostile one can declare a script
/// length that does not match the bytes it carries, which is enough to make a naive window skip over the miner tag and
/// land on harmlessly-looking bytes: the `SHD1` request is then never read and a shielded reward slips past a network
/// that has private payments off. Two checks close that:
///
/// * A coinbase pays exactly one output and the payload carries exactly that output's script public key (the node
///   writes `miner_data.script_public_key`, which is the script of the coin that pays the miner), so both the declared
///   length and the script bytes must be the ones in the coinbase's own output. Anything else is a lie by the only
///   party who writes the payload, and nothing is read through it (see `check_coinbase_shielded_tag`).
/// * Neither the version nor the script may run past the end of the payload: a script public key that does not fit is
///   not a script, and there is no miner tag behind it.
fn coinbase_miner_tag<'a>(tx: &'a Transaction, payload: &'a [u8]) -> Option<&'a [u8]> {
    /// Blue score (8) + subsidy (8) + pool state (5 × 8) + coin list root (32) + private state (32) + script public key
    /// version (2)
    const COINBASE_HEAD_LEN: usize = 8 + 8 + 5 * 8 + 32 + 32 + 2;
    let script_len = *payload.get(COINBASE_HEAD_LEN)? as usize;
    let script = tx.outputs.first()?.script_public_key.script();
    if script_len != script.len() || payload.get(COINBASE_HEAD_LEN + 1..COINBASE_HEAD_LEN + 1 + script_len) != Some(script) {
        return None;
    }
    payload.get(COINBASE_HEAD_LEN + 1 + script_len..)
}

/// Zethora (ZTH-SPEC-006 §7.4): a coinbase whose miner tag asks for a private reward (`SHD1`) needs private payments,
/// so when `spends_enabled` is false it is refused like any other private payment: a plain refusal, not a proof error,
/// so no peer is banned for it (nodes on different rule versions may disagree about it).
///
/// The tag is looked for anywhere in the miner tag, not only at its start: the node's own version string comes first
/// (`version()` in the RPC data flow), and a miner that renames itself must not slip a private reward past this check.
/// Matching the miner rather than a fixed offset also keeps an ordinary reward whose script happens to contain the
/// four bytes from being refused.
///
/// A payload that carries the tag where this node cannot place it is refused, so a script length the coinbase does not
/// have can never hide a request (`coinbase_miner_tag`). The length byte alone does not decide either way: a payload
/// whose only `SHD1` bytes are inside its own payout script asks for nothing, and a payload with no tag in it at all is
/// never refused, so "never refuse a flag we cannot read" holds for everything that is not a request.
fn check_coinbase_shielded_tag(tx: &Transaction, spends_enabled: bool) -> TxResult<()> {
    if spends_enabled {
        return Ok(());
    }
    // The miner tag carries no payload the parser has to reach, so the whole payload may be searched for the prefix.
    let carries_tag = contains_tag(&tx.payload);
    if !carries_tag {
        return Ok(());
    }
    let refused = || {
        TxRuleError::InvalidPrivatePayment(
            "a private (shielded) coinbase reward needs private payments, which are disabled on this network (ZTH-SPEC-006 §7.3/§7.4)"
                .to_string(),
        )
    };
    // The usual case: the miner tag is where `CoinbaseManager` puts it, and a request there is a request.
    if coinbase_miner_tag(tx, &tx.payload).is_some_and(contains_tag) {
        return Err(refused());
    }
    // The tag is in the payload but not in a miner tag the parser can locate, so this node cannot say what it means.
    // Whether a miner could have written it on purpose decides:
    // * The only `SHD1` is inside the payout script. A miner tag lives after the script public key and never inside it,
    //   so this is not a request, and refusing it would let one miner's address decide whether another miner's block is
    //   valid.
    if let Some(script) = tx.outputs.first().map(|output| output.script_public_key.script())
        && contains_tag(script)
        && !tag_outside_script(&tx.payload, script)
    {
        return Ok(());
    }
    // * Everything else - a tag in the extra data behind a window this node cannot place, a tag in the script *and*
    //   outside it, a script that is not the one the payload carries - is a request this node has to read. Refused, so
    //   no crafted length byte can make a shielded reward spendable on a network where the pool is closed.
    Err(refused())
}

/// Whether the four bytes of the shielded miner tag appear in `bytes`.
fn contains_tag(bytes: &[u8]) -> bool {
    bytes.windows(SHIELDED_TAG_PREFIX.len()).any(|window| window == SHIELDED_TAG_PREFIX)
}

/// Whether `bytes` carries the tag somewhere other than inside `script`: it contains the tag, and it carries at least
/// one more occurrence of those bytes than `script` does. Counting, rather than searching outside the script's bytes,
/// needs no assumption about where in `bytes` the script sits.
fn tag_outside_script(bytes: &[u8], script: &[u8]) -> bool {
    let count = |haystack: &[u8]| haystack.windows(SHIELDED_TAG_PREFIX.len()).filter(|w| *w == SHIELDED_TAG_PREFIX).count();
    contains_tag(bytes) && count(bytes) > count(script)
}

fn check_gas(tx: &Transaction) -> TxResult<()> {
    if tx.gas == 0 {
        return Ok(());
    }

    if tx.version < TX_VERSION_TOCCATA {
        return Err(TxRuleError::TxHasGas("gas is only allowed for Toccata-or-newer tx versions"));
    }

    // Only post-Toccata non-system lanes may carry gas; reserved system lanes
    // have a 19-byte zero suffix and must remain gas-free.
    if !matches!(tx.subnetwork_id.as_bytes(), [_x, rest @ ..] if rest == ZEROES_19) {
        return Ok(());
    }

    Err(TxRuleError::TxHasGas("native / system subnetworks must use zero gas"))
}

fn check_transaction_version(tx: &Transaction) -> TxResult<()> {
    if tx.version > TX_VERSION_TOCCATA {
        return Err(TxRuleError::UnknownTxVersion(tx.version));
    }
    Ok(())
}

fn check_transaction_output_value_ranges(tx: &Transaction) -> TxResult<()> {
    let mut total: u64 = 0;
    for (i, output) in tx.outputs.iter().enumerate() {
        if output.value == 0 {
            return Err(TxRuleError::TxOutZero(i));
        }

        if output.value > MAX_ZETS {
            return Err(TxRuleError::TxOutTooHigh(i));
        }

        if let Some(new_total) = total.checked_add(output.value) {
            total = new_total
        } else {
            return Err(TxRuleError::OutputsValueOverflow);
        }

        if total > MAX_ZETS {
            return Err(TxRuleError::TotalTxOutTooHigh);
        }
    }

    Ok(())
}

fn check_transaction_subnetwork(tx: &Transaction) -> TxResult<()> {
    const ZEROES_16: &[u8; SUBNETWORK_ZERO_TAIL_LEN] = &[0; SUBNETWORK_ZERO_TAIL_LEN];

    // KIP-21 subnetwork ID shape, checked in priority order:
    // - `[x, 0×19]` (19-byte zero suffix): reserved system ID. Only NATIVE and
    //   COINBASE first bytes are valid; every other `x` is reserved for future
    //   system use and rejected.
    // - `[namespace (4 bytes), 0×16]`: user lane. Any first byte is allowed.
    //   Since the 19-suffix case is handled above, at least one of
    //   `bytes[1..4]` is non-zero, so the namespace is never all-zero here.
    //   Gated behind the Toccata HF.
    // - Any other shape: rejected.
    match tx.subnetwork_id.as_bytes() {
        // Native and coinbase (reserved) subnetwork IDs are always allowed
        [NativeSubnetwork::FIRST_BYTE, rest @ ..] | [CoinbaseSubnetwork::FIRST_BYTE, rest @ ..] if rest == ZEROES_19 => Ok(()),
        [_x, rest @ ..] if rest == ZEROES_19 => Err(TxRuleError::SubnetworksDisabled(tx.subnetwork_id)),
        bytes if tx.version >= TX_VERSION_TOCCATA && &bytes[SUBNETWORK_NAMESPACE_LEN..] == ZEROES_16 => Ok(()),
        _ => Err(TxRuleError::SubnetworksDisabled(tx.subnetwork_id)),
    }
}

fn check_tx_version_specific_fields(tx: &Transaction) -> TxResult<()> {
    if tx.version > 0 {
        for (i, input) in tx.inputs.iter().enumerate() {
            if let Some(sig_op_count) = input.compute_commit.sig_op_count() {
                return Err(TxRuleError::SigopCountInV1(i, sig_op_count));
            }
        }
    } else {
        for (i, input) in tx.inputs.iter().enumerate() {
            if let Some(compute_budget) = input.compute_commit.compute_budget() {
                return Err(TxRuleError::ComputeBudgetInV0(i, compute_budget));
            }
        }

        for (i, output) in tx.outputs.iter().enumerate() {
            if output.covenant.is_some() {
                return Err(TxRuleError::CovenantBindingInV0(i));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use kaspa_consensus_core::{
        constants::{TX_VERSION, TX_VERSION_TOCCATA},
        subnets::{SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE, SubnetworkId},
        tx::{
            ComputeCommit, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput,
            scriptvec,
        },
    };
    use kaspa_core::assert_match;

    use crate::{
        params::MAINNET_PARAMS,
        processes::transaction_validator::{TransactionValidator, errors::TxRuleError},
    };

    #[test]
    fn validate_tx_in_isolation_test() {
        let mut params = MAINNET_PARAMS.clone();
        params.max_tx_inputs = 10;
        params.max_tx_outputs = 15;
        let tv = TransactionValidator::new_for_tests(
            params.max_tx_inputs,
            params.max_tx_outputs,
            params.max_signature_script_len,
            params.max_script_public_key_len,
            params.coinbase_payload_script_public_key_max_len,
            params.coinbase_maturity(),
            params.ghostdag_k(),
            Default::default(),
        );

        let valid_cb = Transaction::new(
            0,
            vec![],
            vec![TransactionOutput {
                value: 0x12a05f200,
                script_public_key: ScriptPublicKey::new(
                    0,
                    scriptvec!(
                        0xa9, 0x14, 0xda, 0x17, 0x45, 0xe9, 0xb5, 0x49, 0xbd, 0x0b, 0xfa, 0x1a, 0x56, 0x99, 0x71, 0xc7, 0x7e, 0xba,
                        0x30, 0xcd, 0x5a, 0x4b, 0x87
                    ),
                ),
                covenant: None,
            }],
            0,
            SUBNETWORK_ID_COINBASE,
            0,
            vec![9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );

        tv.validate_tx_in_isolation(&valid_cb).unwrap();

        let valid_tx = Transaction::new(
            0,
            vec![TransactionInput {
                previous_outpoint: TransactionOutpoint {
                    transaction_id: TransactionId::from_slice(&[
                        0x03, 0x2e, 0x38, 0xe9, 0xc0, 0xa8, 0x4c, 0x60, 0x46, 0xd6, 0x87, 0xd1, 0x05, 0x56, 0xdc, 0xac, 0xc4, 0x1d,
                        0x27, 0x5e, 0xc5, 0x5f, 0xc0, 0x07, 0x79, 0xac, 0x88, 0xfd, 0xf3, 0x57, 0xa1, 0x87,
                    ]),
                    index: 0,
                },
                signature_script: vec![
                    0x49, // OP_DATA_73
                    0x30, 0x46, 0x02, 0x21, 0x00, 0xc3, 0x52, 0xd3, 0xdd, 0x99, 0x3a, 0x98, 0x1b, 0xeb, 0xa4, 0xa6, 0x3a, 0xd1, 0x5c,
                    0x20, 0x92, 0x75, 0xca, 0x94, 0x70, 0xab, 0xfc, 0xd5, 0x7d, 0xa9, 0x3b, 0x58, 0xe4, 0xeb, 0x5d, 0xce, 0x82, 0x02,
                    0x21, 0x00, 0x84, 0x07, 0x92, 0xbc, 0x1f, 0x45, 0x60, 0x62, 0x81, 0x9f, 0x15, 0xd3, 0x3e, 0xe7, 0x05, 0x5c, 0xf7,
                    0xb5, 0xee, 0x1a, 0xf1, 0xeb, 0xcc, 0x60, 0x28, 0xd9, 0xcd, 0xb1, 0xc3, 0xaf, 0x77, 0x48,
                    0x01, // 73-byte signature
                    0x41, // OP_DATA_65
                    0x04, 0xf4, 0x6d, 0xb5, 0xe9, 0xd6, 0x1a, 0x9d, 0xc2, 0x7b, 0x8d, 0x64, 0xad, 0x23, 0xe7, 0x38, 0x3a, 0x4e, 0x6c,
                    0xa1, 0x64, 0x59, 0x3c, 0x25, 0x27, 0xc0, 0x38, 0xc0, 0x85, 0x7e, 0xb6, 0x7e, 0xe8, 0xe8, 0x25, 0xdc, 0xa6, 0x50,
                    0x46, 0xb8, 0x2c, 0x93, 0x31, 0x58, 0x6c, 0x82, 0xe0, 0xfd, 0x1f, 0x63, 0x3f, 0x25, 0xf8, 0x7c, 0x16, 0x1b, 0xc6,
                    0xf8, 0xa6, 0x30, 0x12, 0x1d, 0xf2, 0xb3, 0xd3, // 65-byte pubkey
                ],
                sequence: u64::MAX,
                compute_commit: ComputeCommit::SigopCount(0.into()),
            }],
            vec![
                TransactionOutput {
                    value: 0x2123e300,
                    script_public_key: ScriptPublicKey::new(
                        0,
                        scriptvec!(
                            0x76, // OP_DUP
                            0xa9, // OP_HASH160
                            0x14, // OP_DATA_20
                            0xc3, 0x98, 0xef, 0xa9, 0xc3, 0x92, 0xba, 0x60, 0x13, 0xc5, 0xe0, 0x4e, 0xe7, 0x29, 0x75, 0x5e, 0xf7,
                            0xf5, 0x8b, 0x32, 0x88, // OP_EQUALVERIFY
                            0xac  // OP_CHECKSIG
                        ),
                    ),
                    covenant: None,
                },
                TransactionOutput {
                    value: 0x108e20f00,
                    script_public_key: ScriptPublicKey::new(
                        0,
                        scriptvec!(
                            0x76, // OP_DUP
                            0xa9, // OP_HASH160
                            0x14, // OP_DATA_20
                            0x94, 0x8c, 0x76, 0x5a, 0x69, 0x14, 0xd4, 0x3f, 0x2a, 0x7a, 0xc1, 0x77, 0xda, 0x2c, 0x2f, 0x6b, 0x52,
                            0xde, 0x3d, 0x7c, 0x88, // OP_EQUALVERIFY
                            0xac  // OP_CHECKSIG
                        ),
                    ),
                    covenant: None,
                },
            ],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        );

        tv.validate_tx_in_isolation(&valid_tx).unwrap();

        let mut tx: Transaction = valid_tx.clone();
        tx.subnetwork_id = SubnetworkId::from_byte(3);
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::SubnetworksDisabled(_)));

        let mut tx = valid_tx.clone();
        tx.inputs = vec![];
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::NoTxInputs));

        // Zethora: no visible input is allowed only for a private payment that pays from the private pool
        let fake_private = |value_balance: i64| {
            let mut payload = kaspa_consensus_core::zethora_private::PRIVATE_PAYMENT_MAGIC.to_vec();
            payload.push(1); // pool version
            payload.extend_from_slice(&2u16.to_le_bytes());
            payload.extend(std::iter::repeat_n(0u8, 2 * kaspa_consensus_core::zethora_private::ACTION_SIZE));
            payload.push(0b11); // flags
            payload.extend_from_slice(&value_balance.to_le_bytes());
            payload
        };
        let mut tx = valid_tx.clone();
        tx.inputs = vec![];
        tx.payload = fake_private(0);
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::NoTxInputs));
        tx.payload = fake_private(-5_000);
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::NoTxInputs));
        tx.payload = fake_private(1_000);
        assert_match!(tv.check_transaction_inputs_count(&tx), Ok(()));
        // ... and it still has to be a real private payment (this fake one can't even be read: a plain refusal)
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::InvalidPrivatePayment(_)));

        let mut tx = valid_tx.clone();
        tx.inputs = (0..params.max_tx_inputs + 1).map(|_| valid_tx.inputs[0].clone()).collect();
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::TooManyInputs(_, _)));

        let mut tx = valid_tx.clone();
        tx.inputs[0].signature_script = vec![0; params.max_signature_script_len + 1];
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::TooBigSignatureScript(_, _)));

        let mut tx = valid_tx.clone();
        tx.outputs = (0..params.max_tx_outputs + 1).map(|_| valid_tx.outputs[0].clone()).collect();
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::TooManyOutputs(_, _)));

        let mut tx = valid_tx.clone();
        tx.outputs[0].script_public_key = ScriptPublicKey::new(0, scriptvec![0u8; params.max_script_public_key_len + 1]);
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::TooBigScriptPublicKey(_, _)));

        let mut tx = valid_tx.clone();
        tx.inputs.push(tx.inputs[0].clone());
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::TxDuplicateInputs));

        let mut tx = valid_tx.clone();
        tx.gas = 1;
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::TxHasGas(_)));

        let mut tx = valid_tx.clone();
        tx.payload = vec![0];
        assert_match!(tv.validate_tx_in_isolation(&tx), Ok(()));

        let mut tx = valid_tx.clone();
        tx.version = 1;
        tx.inputs[0].compute_commit = ComputeCommit::SigopCount(1.into());
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::SigopCountInV1(_, _)));

        let mut tx = valid_tx.clone();
        tx.version = 0;
        tx.inputs[0].compute_commit = ComputeCommit::ComputeBudget(1.into());
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::ComputeBudgetInV0(_, _)));

        let mut tx = valid_tx;
        tx.version = TX_VERSION_TOCCATA + 1;
        assert_match!(tv.validate_tx_in_isolation(&tx), Err(TxRuleError::UnknownTxVersion(_)));
    }

    #[test]
    fn check_transaction_subnetwork_shape() {
        use kaspa_consensus_core::subnets::{SUBNETWORK_ID_SIZE, SUBNETWORK_NAMESPACE_LEN, SUBNETWORK_ZERO_TAIL_LEN, SubnetworkId};
        use kaspa_consensus_core::tx::TransactionOutpoint;

        fn sid(namespace: [u8; SUBNETWORK_NAMESPACE_LEN], tail: [u8; SUBNETWORK_ZERO_TAIL_LEN]) -> SubnetworkId {
            let mut bytes = [0u8; SUBNETWORK_ID_SIZE];
            bytes[..SUBNETWORK_NAMESPACE_LEN].copy_from_slice(&namespace);
            bytes[SUBNETWORK_NAMESPACE_LEN..].copy_from_slice(&tail);
            SubnetworkId::from_bytes(bytes)
        }

        fn tx_with(subnetwork_id: SubnetworkId, version: u16) -> Transaction {
            // Minimal tx: one input + one output so only the subnetwork check is exercised here.
            let input = TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: TransactionId::from_slice(&[0u8; 32]), index: 0 },
                signature_script: vec![],
                sequence: 0,
                compute_commit: ComputeCommit::SigopCount(0.into()),
            };
            let output = TransactionOutput { value: 1, script_public_key: ScriptPublicKey::new(0, scriptvec!(0u8)), covenant: None };
            Transaction::new(version, vec![input], vec![output], 0, subnetwork_id, 0, vec![])
        }

        // Reserved IDs (19-byte zero suffix): native/coinbase only, allowed at any version.
        for version in [TX_VERSION, TX_VERSION_TOCCATA] {
            super::check_transaction_subnetwork(&tx_with(SUBNETWORK_ID_NATIVE, version)).unwrap();
            super::check_transaction_subnetwork(&tx_with(SUBNETWORK_ID_COINBASE, version)).unwrap();
        }

        // [x, 0×19] for any x ∉ {NATIVE, COINBASE} → rejected at every version.
        // The 19-suffix shape is reserved for system use; only the two system
        // first bytes are valid. A namespace of `[x, 0, 0, 0]` must NOT sneak
        // through to the user-lane arm.
        for byte in [0x02u8, 0x07, 0xff] {
            let reserved_shape = SubnetworkId::from_byte(byte);
            for version in [TX_VERSION, TX_VERSION_TOCCATA] {
                assert_match!(
                    super::check_transaction_subnetwork(&tx_with(reserved_shape, version)),
                    Err(TxRuleError::SubnetworksDisabled(_))
                );
            }
        }

        // User lane [namespace, 0×16] with a non-zero byte in bytes[1..4]
        // — any first byte (including native/coinbase) is accepted post-cov-HF.
        for namespace in [[0x11, 0x22, 0x33, 0x44], [0x00, 0x00, 0x00, 0x01], [0xde, 0xad, 0xbe, 0xef], [0x07, 0x01, 0, 0]] {
            let lane = sid(namespace, [0; SUBNETWORK_ZERO_TAIL_LEN]);
            super::check_transaction_subnetwork(&tx_with(lane, TX_VERSION_TOCCATA)).unwrap();
            // Pre-HF: user lanes are forbidden.
            assert_match!(super::check_transaction_subnetwork(&tx_with(lane, TX_VERSION)), Err(TxRuleError::SubnetworksDisabled(_)));
        }

        // Non-zero tail → rejected even post-HF.
        let mut dirty_tail = [0u8; SUBNETWORK_ZERO_TAIL_LEN];
        dirty_tail[0] = 1;
        let tail_byte_set = sid([0x11, 0, 0, 0], dirty_tail);
        assert_match!(
            super::check_transaction_subnetwork(&tx_with(tail_byte_set, TX_VERSION_TOCCATA)),
            Err(TxRuleError::SubnetworksDisabled(_))
        );
        let mut dirty_tail_last = [0u8; SUBNETWORK_ZERO_TAIL_LEN];
        *dirty_tail_last.last_mut().unwrap() = 0xff;
        let tail_last_set = sid([0, 0, 0, 1], dirty_tail_last);
        assert_match!(
            super::check_transaction_subnetwork(&tx_with(tail_last_set, TX_VERSION_TOCCATA)),
            Err(TxRuleError::SubnetworksDisabled(_))
        );

        let user_lane = sid([0, 0, 0, 1], [0; SUBNETWORK_ZERO_TAIL_LEN]);
        let reserved_shape = SubnetworkId::from_byte(2);
        for (subnetwork_id, version, gas_allowed) in [
            (SUBNETWORK_ID_NATIVE, TX_VERSION_TOCCATA, false),
            (SUBNETWORK_ID_COINBASE, TX_VERSION_TOCCATA, false),
            (reserved_shape, TX_VERSION_TOCCATA, false),
            (user_lane, TX_VERSION, false),
            (user_lane, TX_VERSION_TOCCATA, true),
        ] {
            let mut tx = tx_with(subnetwork_id, version);
            tx.gas = 1;
            assert_match!((super::check_gas(&tx), gas_allowed), (Ok(()), true) | (Err(TxRuleError::TxHasGas(_)), false));
        }
    }
}

#[cfg(test)]
mod zethora_private_payment_tests {
    use super::{TxRuleError, check_private_payment};
    use kaspa_consensus_core::{
        constants::TX_VERSION,
        hashing::tx::zethora_private_payment_digest,
        subnets::{SUBNETWORK_ID_COINBASE, SUBNETWORK_ID_NATIVE},
        tx::{ComputeCommit, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint, TransactionOutput, scriptvec},
        zethora_private::{ACTION_SIZE, PRIVATE_PAYMENT_MAGIC},
    };
    use kaspa_hashes::Hash;
    use zethora_shielded::wallet::{PrivateWallet, shielding_payment};

    /// The genesis hash these tests' "network" signs (seam review pack 1 #6)
    const TEST_GENESIS: Hash = Hash::from_bytes([0x6E; 32]);

    fn base_tx() -> Transaction {
        let input = TransactionInput {
            previous_outpoint: TransactionOutpoint::new(Hash::from_u64_word(7), 0),
            signature_script: vec![],
            sequence: 0,
            compute_commit: ComputeCommit::SigopCount(1.into()),
        };
        let output =
            TransactionOutput { value: 1_000_000, script_public_key: ScriptPublicKey::new(0, scriptvec![0x51]), covenant: None };
        Transaction::new_non_finalized(TX_VERSION, vec![input], vec![output], 0, SUBNETWORK_ID_NATIVE, 0, vec![])
    }

    fn shielding_tx(amount: u64) -> Transaction {
        let mut tx = base_tx();
        let digest = zethora_private_payment_digest(&tx, &TEST_GENESIS);
        let payment = shielding_payment(PrivateWallet::from_seed(&[5; 32]).address(), amount, &digest.as_bytes()).unwrap();
        tx.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(payment).collect();
        tx
    }

    #[test]
    fn action_size_matches_the_codec() {
        assert_eq!(ACTION_SIZE, zethora_shielded::codec::ACTION_SIZE);
    }

    #[test]
    fn ordinary_payloads_are_untouched() {
        let mut tx = base_tx();
        assert_eq!(check_private_payment(&tx, false, &TEST_GENESIS), Ok(()));
        tx.payload = b"just some data".to_vec();
        assert_eq!(check_private_payment(&tx, false, &TEST_GENESIS), Ok(()));
    }

    #[test]
    fn valid_shielding_payment_is_accepted_and_bound_to_its_transaction() {
        let tx = shielding_tx(500_000);
        assert_eq!(check_private_payment(&tx, true, &TEST_GENESIS), Ok(()));

        // Change the visible part (send more to the output): the private payment no longer matches
        let mut moved = tx.clone();
        moved.outputs[0].value += 1;
        assert!(matches!(check_private_payment(&moved, true, &TEST_GENESIS), Err(TxRuleError::InvalidPrivatePaymentProof(_))));

        // Changing only signature scripts does not affect it (they are signed separately)
        let mut resigned = tx.clone();
        resigned.inputs[0].signature_script = vec![1, 2, 3];
        assert_eq!(check_private_payment(&resigned, true, &TEST_GENESIS), Ok(()));
    }

    #[test]
    fn shielding_is_accepted_when_spends_on() {
        // Devnet and simnet: adding coins to the pool works; the proof binding
        // check still runs.
        let tx = shielding_tx(500_000);
        assert_eq!(check_private_payment(&tx, true, &TEST_GENESIS), Ok(()));
        let mut moved = tx.clone();
        moved.outputs[0].value += 1;
        assert!(matches!(check_private_payment(&moved, true, &TEST_GENESIS), Err(TxRuleError::InvalidPrivatePaymentProof(_))));
    }

    #[test]
    fn private_payments_are_refused_when_spends_off() {
        // Testnet and mainnet: every private payment is refused at isolation time,
        // before decode and proof. Plain refusal, not a proof error, so no peer is
        // banned for it. Both paths below are covered: shielding (which used to
        // pass) and fully private (which already refused at value_balance > 0).
        let shield = shielding_tx(500_000);
        assert!(matches!(check_private_payment(&shield, false, &TEST_GENESIS), Err(TxRuleError::InvalidPrivatePayment(_))));
        let spend = fully_private_tx(1_000);
        assert!(matches!(check_private_payment(&spend, false, &TEST_GENESIS), Err(TxRuleError::InvalidPrivatePayment(_))));
    }

    /// Zethora (ZTH-SPEC-006 §7.4): a coinbase that asks for its reward in a private address carries `SHD1` in its
    /// miner tag. Paying it is a private payment the node makes, so with private payments off it is refused like any
    /// other: `InvalidPrivatePayment`, never a proof error (no peer is banned for it), and without any other work.
    #[test]
    fn shielded_coinbase_reward_is_refused_when_spends_off() {
        let coinbase = shielded_coinbase_tx(true);
        assert!(coinbase.is_coinbase());
        assert_eq!(check_private_payment(&coinbase, true, &TEST_GENESIS), Ok(()));
        assert!(matches!(check_private_payment(&coinbase, false, &TEST_GENESIS), Err(TxRuleError::InvalidPrivatePayment(_))));

        // The whole isolation check (the one a node runs on every block's coinbase) refuses it too
        let tv = crate::processes::transaction_validator::TransactionValidator::new_for_tests(
            1000,
            1000,
            10_000,
            150,
            150,
            100,
            18,
            Default::default(),
        )
        .with_zethora_genesis(TEST_GENESIS)
        .with_private_spends(false);
        assert!(matches!(tv.validate_tx_in_isolation(&coinbase), Err(TxRuleError::InvalidPrivatePayment(_))));
    }

    /// The other side of the rule: an ordinary coinbase is untouched on a network with private payments off, and a
    /// shielded one is accepted on a network with them on.
    #[test]
    fn ordinary_coinbase_rewards_are_untouched_when_spends_off() {
        let ordinary = shielded_coinbase_tx(false);
        assert_eq!(check_private_payment(&ordinary, false, &TEST_GENESIS), Ok(()));
        // The four bytes inside the script public key (a miner address that looks like `SHD1`) are not a request:
        // only the miner tag decides
        assert!(ordinary.outputs[0].script_public_key.script().windows(4).any(|w| w == SHIELDED_TAG_PREFIX));
        assert_eq!(check_private_payment(&ordinary, true, &TEST_GENESIS), Ok(()));

        // The node's own version string comes before the miner's, so the tag is found anywhere in the miner tag
        let mut renamed = shielded_coinbase_tx(true);
        renamed.payload.splice(coinbase_miner_tag_start()..coinbase_miner_tag_start(), b"rusty-kaspad/v1.0.0".iter().copied());
        assert!(matches!(check_private_payment(&renamed, false, &TEST_GENESIS), Err(TxRuleError::InvalidPrivatePayment(_))));
    }

    /// First four bytes of the shielded miner tag (ZTH-SPEC-006 §7.4). Defined here, not shared with the miner, so
    /// these tests pin the bytes the two sides agreed on: if either side renames the tag, a test fails.
    const SHIELDED_TAG_PREFIX: [u8; 4] = *b"SHD1";

    /// First bytes of the miner tag in a coinbase payload: blue score (8) + subsidy (8) + pool state (5 × 8) +
    /// coin list root (32) + private state (32) + script public key version (2) + script public key length (1), then
    /// the script public key, then the miner tag (consensus/src/processes/coinbase.rs).
    const COINBASE_MINER_TAG_AT: usize = 8 + 8 + 5 * 8 + 32 + 32 + 2 + 1;

    /// Length of the payout script `shielded_coinbase_tx` writes: `0xa9, 0x14`, the four `SHD1` bytes and 18 zero
    /// bytes (a pay-to-pubkey-hash script that itself contains the tag).
    const PAYOUT_SCRIPT_LEN: usize = 2 + 4 + 18;

    fn coinbase_miner_tag_start() -> usize {
        COINBASE_MINER_TAG_AT + PAYOUT_SCRIPT_LEN
    }

    /// A coinbase shaped the way `CoinbaseManager` writes one. `shielded` puts the miner's `SHD1 | pool version |
    /// Orchard address` tag in the extra data, exactly as `zethora-miner --shielded` does.
    fn shielded_coinbase_tx(shielded: bool) -> Transaction {
        // A pay-to-pubkey-hash script that itself contains "SHD1": the rule must look at the miner tag, not the script
        let script = scriptvec![0xa9, 0x14, b'S', b'H', b'D', b'1', 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8];
        let mut payload = Vec::with_capacity(COINBASE_MINER_TAG_AT + PAYOUT_SCRIPT_LEN + 48);
        payload.extend_from_slice(&9u64.to_le_bytes()); // blue score
        payload.extend_from_slice(&1_000_000u64.to_le_bytes()); // subsidy
        payload.extend_from_slice(&[0u8; 5 * 8]); // Zethora pool state
        payload.extend_from_slice(&[0x11u8; 32]); // coin list root
        payload.extend_from_slice(&[0x22u8; 32]); // private state fingerprint
        payload.extend_from_slice(&0u16.to_le_bytes()); // script public key version
        payload.push(script.len() as u8);
        payload.extend_from_slice(&script);
        if shielded {
            payload.extend_from_slice(&SHIELDED_TAG_PREFIX);
            payload.push(1); // Orchard pool version
            payload.extend_from_slice(&[0x33u8; 43]); // Orchard address: diversifier (11) + transmission key (32)
        } else {
            payload.extend_from_slice(b"zethora-miner");
        }
        Transaction::new(
            TX_VERSION,
            vec![],
            vec![TransactionOutput { value: 1_000_000, script_public_key: ScriptPublicKey::new(0, script), covenant: None }],
            0,
            SUBNETWORK_ID_COINBASE,
            0,
            payload,
        )
    }

    /// A fully private payment (ZTH-SPEC-006 §9): no visible input or output; `fee` zets leave the private pool
    /// as the network fee. The coin it spends comes from a shield in a coin list the test builds itself.
    fn fully_private_tx(fee: u64) -> Transaction {
        use zethora_shielded::scan::Scanner;
        let (me, friend) = (PrivateWallet::from_seed(&[5; 32]), PrivateWallet::friend_of(&[5; 32]));
        let (me_address, friend_address) = (me.address(), friend.address());
        let mut scanner = Scanner::new(vec![me, friend]);
        scanner.add_payment(&shielding_payment(me_address, 50_000, &[0; 32]).unwrap()).unwrap();
        scanner.checkpoint().unwrap();
        let coins = scanner.pick_coins(0, 50_000).unwrap();
        let mut tx = Transaction::new_non_finalized(TX_VERSION, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
        let digest = zethora_private_payment_digest(&tx, &TEST_GENESIS);
        let payment =
            scanner.spend_payment(0, &coins, &[(friend_address, 30_000), (me_address, 20_000 - fee)], &digest.as_bytes()).unwrap();
        tx.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(payment).collect();
        tx.finalize();
        tx
    }

    #[test]
    fn fully_private_payment_needs_no_visible_coin() {
        let tv = crate::processes::transaction_validator::TransactionValidator::new_for_tests(
            1000,
            1000,
            10_000,
            150,
            150,
            100,
            18,
            Default::default(),
        );
        let tx = fully_private_tx(1_000);
        assert!(tx.inputs.is_empty() && tx.outputs.is_empty());
        assert!(kaspa_consensus_core::zethora_private::pays_from_private_pool(&tx.payload));
        assert_eq!(tv.check_transaction_inputs_count(&tx), Ok(()));
        let mut locked = tx.clone();
        locked.lock_time = 5;
        assert!(matches!(tv.check_transaction_inputs_count(&locked), Err(TxRuleError::InvalidPrivatePayment(_))));
        // Real proof and signatures, bound to this (empty) visible part; spends must be switched on for the network
        assert_eq!(check_private_payment(&tx, true, &TEST_GENESIS), Ok(()));
        // Spends switched off: a plain refusal, not a ban (nodes on different rule versions may disagree)
        assert!(matches!(check_private_payment(&tx, false, &TEST_GENESIS), Err(TxRuleError::InvalidPrivatePayment(_))));

        // The fee is what leaves the pool: nothing visible in, nothing visible out
        let populated = kaspa_consensus_core::tx::PopulatedTransaction::new(&tx, vec![]);
        let fee = tv
            .validate_populated_transaction_and_get_fee(
                &populated,
                1_000,
                1_000,
                crate::processes::transaction_validator::tx_validation_in_utxo_context::TxValidationFlags::Full,
                None,
                None,
            )
            .unwrap();
        assert_eq!(fee, 1_000);

        // Nobody can redirect the fee: adding a visible output breaks the private payment's signatures
        let mut stolen = tx.clone();
        stolen.outputs.push(TransactionOutput {
            value: 1_000,
            script_public_key: ScriptPublicKey::new(0, scriptvec![0x51]),
            covenant: None,
        });
        assert!(matches!(check_private_payment(&stolen, true, &TEST_GENESIS), Err(TxRuleError::InvalidPrivatePaymentProof(_))));
    }

    /// Seam review pack 1 #6 (test T6): the digest a private payment signs covers every field it is documented to
    /// cover, binds the network (genesis hash), and lives in its own hash domain. A fully private payment with one
    /// visible (unshielded) output, transaction version 1 so the output's covenant is covered too.
    #[test]
    fn private_payment_digest_covers_every_field_and_the_network() {
        use kaspa_consensus_core::{constants::TX_VERSION_TOCCATA, subnets::SubnetworkId, tx::CovenantBinding};
        use zethora_shielded::scan::Scanner;
        let (me, friend) = (PrivateWallet::from_seed(&[5; 32]), PrivateWallet::friend_of(&[5; 32]));
        let me_address = me.address();
        let mut scanner = Scanner::new(vec![me, friend]);
        scanner.add_payment(&shielding_payment(me_address, 50_000, &[0; 32]).unwrap()).unwrap();
        scanner.checkpoint().unwrap();
        let coins = scanner.pick_coins(0, 50_000).unwrap();
        // 10,000 zets leave the pool to a visible output, 1,000 pay the fee, 39,000 stay private
        let output = TransactionOutput { value: 10_000, script_public_key: ScriptPublicKey::new(0, scriptvec![0x51]), covenant: None };
        let mut tx = Transaction::new_non_finalized(TX_VERSION_TOCCATA, vec![], vec![output], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
        let digest = zethora_private_payment_digest(&tx, &TEST_GENESIS);
        let payment = scanner.spend_payment(0, &coins, &[(me_address, 39_000)], &digest.as_bytes()).unwrap();
        tx.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain(payment).collect();
        tx.finalize();

        // Positive control: valid on its own network
        assert_eq!(check_private_payment(&tx, true, &TEST_GENESIS), Ok(()));
        // Network binding: the same transaction on another network is a forgery there
        let other_network = Hash::from_bytes([0x6F; 32]);
        assert_ne!(zethora_private_payment_digest(&tx, &other_network), digest);
        assert!(matches!(check_private_payment(&tx, true, &other_network), Err(TxRuleError::InvalidPrivatePaymentProof(_))));

        // Each covered field, changed alone: the digest changes, and the payment's signatures no longer match
        type Mutation = Box<dyn Fn(&mut Transaction)>;
        let mutations: Vec<(&str, Mutation)> = vec![
            ("version", Box::new(|t| t.version = TX_VERSION)),
            ("lock time", Box::new(|t| t.lock_time = 1)),
            ("gas", Box::new(|t| t.gas = 1)),
            ("subnetwork", Box::new(|t| t.subnetwork_id = SubnetworkId::from_byte(9))),
            ("output value", Box::new(|t| t.outputs[0].value += 1)),
            ("output script version", Box::new(|t| t.outputs[0].script_public_key = ScriptPublicKey::new(1, scriptvec![0x51]))),
            ("output script", Box::new(|t| t.outputs[0].script_public_key = ScriptPublicKey::new(0, scriptvec![0x52]))),
            (
                "output covenant",
                Box::new(|t| {
                    t.outputs[0].covenant = Some(CovenantBinding { authorizing_input: 0, covenant_id: Hash::from_bytes([1; 32]) })
                }),
            ),
            ("an extra output", Box::new(|t| t.outputs.push(t.outputs[0].clone()))),
            (
                "an added input",
                Box::new(|t| {
                    t.inputs.push(TransactionInput {
                        previous_outpoint: TransactionOutpoint::new(Hash::from_u64_word(7), 0),
                        signature_script: vec![],
                        sequence: 0,
                        compute_commit: ComputeCommit::SigopCount(1.into()),
                    })
                }),
            ),
        ];
        for (field, mutate) in &mutations {
            let mut changed = tx.clone();
            mutate(&mut changed);
            assert_ne!(zethora_private_payment_digest(&changed, &TEST_GENESIS), digest, "{field}: digest must change");
            let result = check_private_payment(&changed, true, &TEST_GENESIS);
            if *field == "subnetwork" {
                // Refused before the signatures are even checked (private payments use the native subnetwork only)
                assert!(matches!(result, Err(TxRuleError::InvalidPrivatePayment(_))), "{field}: {result:?}");
            } else {
                assert!(matches!(result, Err(TxRuleError::InvalidPrivatePaymentProof(_))), "{field}: {result:?}");
            }
        }

        // Inputs: outpoint and sequence are covered; the signature script and the compute budget (mass commitment)
        // are not, by design (see zethora_private_payment_digest)
        let with_input = |sequence: u64, index: u32, script: Vec<u8>, budget: u16| {
            let mut t = tx.clone();
            t.version = TX_VERSION_TOCCATA;
            t.inputs.push(TransactionInput {
                previous_outpoint: TransactionOutpoint::new(Hash::from_u64_word(7), index),
                signature_script: script,
                sequence,
                compute_commit: ComputeCommit::ComputeBudget(budget.into()),
            });
            zethora_private_payment_digest(&t, &TEST_GENESIS)
        };
        let base = with_input(0, 0, vec![], 10);
        assert_ne!(with_input(1, 0, vec![], 10), base, "input sequence");
        assert_ne!(with_input(0, 1, vec![], 10), base, "input outpoint index");
        assert_eq!(with_input(0, 0, vec![1, 2, 3], 10), base, "signature scripts are not covered (they sign the payload)");
        assert_eq!(with_input(0, 0, vec![], 11), base, "the compute budget is not covered (mass commitment)");

        // Own domain: the old digest was exactly the version-0 transaction id of the transaction without its payload;
        // the new one never equals it (nor the transaction's id or hash)
        let mut bare = tx.clone();
        bare.payload.clear();
        bare.finalize();
        assert_ne!(digest, kaspa_consensus_core::hashing::tx::id_v0(&bare));
        assert_ne!(digest, bare.id());
        assert_ne!(digest, kaspa_consensus_core::hashing::tx::hash(&bare));
    }

    #[test]
    fn garbage_after_the_marker_is_rejected() {
        let mut tx = base_tx();
        tx.payload = PRIVATE_PAYMENT_MAGIC.iter().copied().chain([1u8, 2, 0, 9, 9]).collect();
        // Unreadable: refused, but no ban (a newer node could send a format this node doesn't know yet)
        assert!(matches!(check_private_payment(&tx, false, &TEST_GENESIS), Err(TxRuleError::InvalidPrivatePayment(_))));
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Adversarial tests (red team) against the coinbase payload parser that reads the shielded miner tag
// (ZTH-SPEC-006 §7.4). Every payload below is attacker-controlled: a miner writes its own coinbase, so this parser
// must never panic, must never read past the payload, and must never let a crafted length byte hide an `SHD1` tag
// from the `private_spends_enabled = false` rejection.
//
// Run: cargo test -p kaspa-consensus --lib zethora_private_payment_tests
// ---------------------------------------------------------------------------------------------------------------
#[cfg(test)]
mod zethora_coinbase_parser_attack_tests {
    use super::{TransactionValidator, TxRuleError, check_private_payment};
    use kaspa_consensus_core::{
        constants::TX_VERSION,
        subnets::SUBNETWORK_ID_COINBASE,
        tx::{ScriptPublicKey, Transaction, TransactionOutput},
    };
    use kaspa_hashes::Hash;

    /// The genesis hash this test's "network" signs (the same value the rest of the isolation tests use).
    const TEST_GENESIS: Hash = Hash::from_bytes([0x6E; 32]);

    /// First four bytes of the shielded miner tag (ZTH-SPEC-006 §7.4).
    const SHIELDED_TAG_PREFIX: [u8; 4] = *b"SHD1";

    /// Blue score (8) + subsidy (8) + pool state (5 × 8) + coin list root (32) + private state (32) + script public key
    /// version (2): the fixed-width head of a coinbase payload, which ends with the script public key *length* byte
    /// (consensus/src/processes/coinbase.rs, `serialize_coinbase_payload`/`deserialize_coinbase_payload`).
    const COINBASE_HEAD_LEN: usize = 8 + 8 + 5 * 8 + 32 + 32 + 2;

    /// The miner tag a miner writes when it asks for its reward in a private address:
    /// `SHD1 | pool version | Orchard address`.
    fn shielded_tag() -> Vec<u8> {
        let mut tag = SHIELDED_TAG_PREFIX.to_vec();
        tag.push(1); // Orchard pool version
        tag.extend_from_slice(&[0x33u8; 43]); // Orchard address: diversifier (11) + transmission key (32)
        tag
    }

    /// The payout script of every coinbase below: 25 bytes, and it does *not* contain `SHD1`. A test that sees the tag
    /// refused therefore knows the miner tag was the reason, and every byte the parser's `COINBASE_HEAD_LEN` reads is
    /// taken from the real payload.
    fn payout_script() -> Vec<u8> {
        vec![0x76, 0xa9, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
             0x11, 0x12, 0x13, 0x14, 0x15, 0x16]
    }

    /// A well-formed coinbase payload, laid out byte for byte like `CoinbaseManager::serialize_coinbase_payload`: the
    /// fixed head, the script public key version, the script length byte, the script, then `miner_tag`.
    fn payload_with_tag(script: &[u8], miner_tag: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(COINBASE_HEAD_LEN + 1 + script.len() + miner_tag.len());
        payload.extend_from_slice(&9u64.to_le_bytes()); // blue score
        payload.extend_from_slice(&1_000_000u64.to_le_bytes()); // subsidy
        payload.extend_from_slice(&[0u8; 5 * 8]); // Zethora pool state
        payload.extend_from_slice(&[0x11u8; 32]); // coin list root
        payload.extend_from_slice(&[0x22u8; 32]); // private state fingerprint
        payload.extend_from_slice(&0u16.to_le_bytes()); // script public key version
        payload.push(script.len() as u8);
        payload.extend_from_slice(script);
        payload.extend_from_slice(miner_tag);
        payload
    }

    fn coinbase_with_payload(payload: Vec<u8>) -> Transaction {
        let output = TransactionOutput {
            value: 1_000_000,
            script_public_key: ScriptPublicKey::from_vec(0, payout_script()),
            covenant: None,
        };
        Transaction::new(TX_VERSION, vec![], vec![output], 0, SUBNETWORK_ID_COINBASE, 0, payload)
    }

    /// The validator a testnet node builds: private payments off (ZTH-SPEC-006 §7.3 level (a)).
    fn testnet_validator() -> TransactionValidator {
        TransactionValidator::new_for_tests(1000, 1000, 10_000, 150, 150, 100, 18, Default::default())
            .with_zethora_genesis(TEST_GENESIS)
            .with_private_spends(false)
    }

    /// The exact refusal a shielded coinbase must get on a network with private payments off, byte for byte.
    fn shielded_refusal() -> TxRuleError {
        TxRuleError::InvalidPrivatePayment(
            "a private (shielded) coinbase reward needs private payments, which are disabled on this network (ZTH-SPEC-006 §7.3/§7.4)"
                .to_string(),
        )
    }

    /// Control, and the premise of every attack below: an honest shielded coinbase is refused by the *whole*
    /// isolation check on a network with private payments off. If this ever passes, the attacks prove nothing.
    #[test]
    fn control_honest_shielded_coinbase_is_refused_when_spends_off() {
        let coinbase = coinbase_with_payload(payload_with_tag(&payout_script(), &shielded_tag()));
        assert!(coinbase.is_coinbase());
        assert!(!coinbase.outputs[0].script_public_key.script().windows(4).any(|w| w == SHIELDED_TAG_PREFIX));
        assert_eq!(check_private_payment(&coinbase, false, &TEST_GENESIS), Err(shielded_refusal()));
        assert_eq!(testnet_validator().validate_tx_in_isolation(&coinbase), Err(shielded_refusal()));
    }

    /// Control: an ordinary coinbase is untouched, so the refusals above are about the tag and not about coinbases.
    #[test]
    fn control_ordinary_coinbase_is_accepted_when_spends_off() {
        let coinbase = coinbase_with_payload(payload_with_tag(&payout_script(), b"zethora-miner/v1"));
        assert_eq!(check_private_payment(&coinbase, false, &TEST_GENESIS), Ok(()));
        assert_eq!(testnet_validator().validate_tx_in_isolation(&coinbase), Ok(()));
    }

    /// ATTACK 1: out-of-bounds panic. A payload shorter than the fixed head is the state a truncated or hostile
    /// coinbase is in, so the parser must answer `Ok`/`Err` and never panic. Every length from empty up to one byte
    /// short of the head is tried, because a short payload can be *any* length.
    #[test]
    fn attack_short_payload_never_panics() {
        for len in 0..COINBASE_HEAD_LEN {
            // Filled with 0xFF, the worst case: every byte the parser might use as a length is 255.
            let payload = vec![0xFFu8; len];
            let coinbase = coinbase_with_payload(payload);
            assert_eq!(
                check_private_payment(&coinbase, false, &TEST_GENESIS),
                Ok(()),
                "a payload of {len} bytes carries no miner tag, so there is nothing to refuse"
            );
            assert_eq!(
                testnet_validator().validate_tx_in_isolation(&coinbase),
                Ok(()),
                "the whole isolation check must survive a {len}-byte payload"
            );
        }

        // The head itself with no script length byte, no script and no tag is the last short case.
        let mut head_only = payload_with_tag(&[], &[]);
        head_only.truncate(COINBASE_HEAD_LEN);
        assert_eq!(head_only.len(), COINBASE_HEAD_LEN);
        assert_eq!(check_private_payment(&coinbase_with_payload(head_only), false, &TEST_GENESIS), Ok(()));
    }

    /// ATTACK 2: malicious script length. The length byte claims 255 bytes of script while the payload ends far
    /// earlier, so a naive slice from `head + 1 + script_len` is out of bounds. A panic here is a node any miner can
    /// crash with one block, so the parser must handle the missing window safely: a plain `Ok`, never a panic.
    #[test]
    fn attack_lying_script_length_never_panics() {
        let honest = payload_with_tag(&payout_script(), b"");
        assert_eq!(honest.len(), COINBASE_HEAD_LEN + 1 + 25);

        // The attack payload: the head, a length byte that lies (255) and the 25 real script bytes, so the payload ends
        // long before the 255 bytes the length byte claims are before the miner tag.
        let lying: Vec<u8> = honest.iter().copied().enumerate().map(|(i, b)| if i == COINBASE_HEAD_LEN { 255 } else { b }).collect();
        assert_eq!(lying.len(), COINBASE_HEAD_LEN + 1 + 25);
        assert_eq!(lying[COINBASE_HEAD_LEN], 255);
        // Nothing follows the script, so there is no miner tag: the parser must say so, not slice out of bounds.
        assert_eq!(check_private_payment(&coinbase_with_payload(lying), false, &TEST_GENESIS), Ok(()));

        // Every length byte 0..=255 on the same tags-free payload: no value may panic, and none may be refused, since
        // there is never a request to read.
        for script_len in 0u8..=255 {
            let mut payload = payload_with_tag(&payout_script(), b"zethora-miner/v1");
            payload[COINBASE_HEAD_LEN] = script_len;
            assert_eq!(
                check_private_payment(&coinbase_with_payload(payload), false, &TEST_GENESIS),
                Ok(()),
                "script_len byte {script_len} panicked or refused a payload with no tag in it"
            );
        }
    }

    /// ATTACK 3: tag smuggling. The attacker writes a `script_len` that makes the parser *skip over* the `SHD1` tag and
    /// land on harmless bytes, hoping the `private_spends_enabled = false` rejection never sees the request.
    ///
    /// The rule that has to hold: a length byte is not what decides. If the payload asks for a private reward, it is
    /// refused whatever the length byte says, and the length byte itself is never a reason to refuse a payload that asks
    /// for nothing. A payload whose only `SHD1` bytes are somewhere a miner tag never is (inside the payout script)
    /// stays accepted, so the fix for this attack must not turn into a rule that punishes an unlucky miner address.
    #[test]
    fn attack_tag_smuggling_cannot_bypass_the_rejection() {
        let script = payout_script();
        let tag = shielded_tag();
        let honest_len = script.len() as u8;

        // (a) The minimal smuggle: the length byte claims 5 bytes of script, so a parser that trusts it lands inside the
        //     payout script and walks 20 bytes short of the tag - and never sees it.
        let mut smuggled = payload_with_tag(&script, &tag);
        smuggled[COINBASE_HEAD_LEN] = 5;
        assert!(smuggled.windows(4).any(|w| w == SHIELDED_TAG_PREFIX), "precondition: the tag bytes are in the payload");
        assert_eq!(
            check_private_payment(&coinbase_with_payload(smuggled.clone()), false, &TEST_GENESIS),
            Err(shielded_refusal()),
            "a script length that hides the tag from the window must not hide the request"
        );
        assert_eq!(
            testnet_validator().validate_tx_in_isolation(&coinbase_with_payload(smuggled)),
            Err(shielded_refusal()),
            "and the whole isolation check must refuse it too"
        );

        // (b) Every single-byte lie, in a payload that really does carry the tag in the miner tag position:
        //     {script} + `SHD1` + pool version + address, which is what `zethora-miner --shielded` writes. The true
        //     length is refused for the request it makes; every other value puts the tag out of view, which is exactly
        //     what the lie is for, so it is refused too - with the same plain refusal, so no peer is banned for a block
        //     that a rule change could make valid.
        for script_len in 0u8..=255 {
            let mut payload = payload_with_tag(&script, &tag);
            payload[COINBASE_HEAD_LEN] = script_len;
            assert_eq!(
                check_private_payment(&coinbase_with_payload(payload), false, &TEST_GENESIS),
                Err(shielded_refusal()),
                "script_len byte {script_len} smuggled a shielded request past the rejection"
            );
        }

        // (c) The one case that is *not* refused, so the fix cannot be "search for SHD1 anywhere and refuse": a payload
        //     that puts the four bytes inside its own payout script, where a miner tag never lives. That is an address,
        //     not a request - covered end to end by `tag_bytes_inside_the_payout_script_are_not_a_request`.
        //
        //     A tag *after* an honest script length is not that case: the miner tag is *extra data*, so a payload whose
        //     extra data carries `SHD1` asks for a private reward even though every byte of it is well formed. Nothing
        //     there has to be refused for being malformed - it is refused for the request it carries, which is the
        //     ordinary rule (`control_honest_shielded_coinbase_is_refused_when_spends_off`). Counting the occurrences in
        //     the script is what keeps these two apart: a plain "search anywhere" would refuse the address in (c)'s
        //     neighbour, and "search only the first bytes after the script" would miss a renamed miner tag.
        let mut later_tag = payload_with_tag(&script, b"zethora-miner/v1");
        later_tag.extend_from_slice(&tag);
        assert_eq!(later_tag[COINBASE_HEAD_LEN], honest_len, "the payload is well formed: it declares its real length");
        assert!(later_tag.windows(4).any(|w| w == SHIELDED_TAG_PREFIX));
        assert_eq!(
            check_private_payment(&coinbase_with_payload(later_tag), false, &TEST_GENESIS),
            Err(shielded_refusal()),
            "a request in the extra data is a request, however well formed the payload is"
        );
    }

    /// The other direction of attack 3, which must NOT become a false refusal: `SHD1` bytes inside the payout script
    /// public key are not a request. An honest miner whose address happens to contain those four bytes keeps its
    /// reward; only the miner tag decides.
    #[test]
    fn tag_bytes_inside_the_payout_script_are_not_a_request() {
        let mut script_with_tag = script_tagged();
        assert_eq!(&script_with_tag[2..6], &SHIELDED_TAG_PREFIX);
        let payload = payload_with_tag(&script_with_tag, b"zethora-miner");
        let output = TransactionOutput {
            value: 1_000_000,
            script_public_key: ScriptPublicKey::from_vec(0, std::mem::take(&mut script_with_tag)),
            covenant: None,
        };
        let coinbase = Transaction::new(TX_VERSION, vec![], vec![output], 0, SUBNETWORK_ID_COINBASE, 0, payload);
        assert!(coinbase.outputs[0].script_public_key.script().windows(4).any(|w| w == SHIELDED_TAG_PREFIX));
        assert_eq!(check_private_payment(&coinbase, false, &TEST_GENESIS), Ok(()));
        assert_eq!(testnet_validator().validate_tx_in_isolation(&coinbase), Ok(()));

        // The same script behind a length byte this node cannot use to place the miner tag (255 rather than 25): the
        // miner tag is unreadable, but the only `SHD1` bytes in the payload are the ones inside the payout script, where
        // a miner tag never starts. So it stays a reward, not a request. A refusal here would let one miner's address
        // decide whether another miner's block is valid.
        let mut lying = payload_with_tag(&script_tagged(), b"zethora-miner");
        lying[COINBASE_HEAD_LEN] = 255;
        let output = TransactionOutput {
            value: 1_000_000,
            script_public_key: ScriptPublicKey::from_vec(0, script_tagged()),
            covenant: None,
        };
        assert_eq!(
            check_private_payment(&Transaction::new(TX_VERSION, vec![], vec![output], 0, SUBNETWORK_ID_COINBASE, 0, lying), false, &TEST_GENESIS),
            Ok(())
        );
    }

    /// The same 25-byte payout script, with `SHD1` moved into bytes 2..6, the position of a real address's hash data.
    fn script_tagged() -> Vec<u8> {
        let mut script = payout_script();
        script[2..6].copy_from_slice(&SHIELDED_TAG_PREFIX);
        script
    }

    /// A payload cut off in the middle of its script has no miner tag at all, so it is ignored: a truncated block body is
    /// a separate rule, not this one. This is the case that keeps the fix for attack 3 honest - a payload that carries no
    /// request is not refused, whatever its length byte says.
    #[test]
    fn a_payload_cut_before_the_miner_tag_is_ignored() {
        let script = payout_script();
        let mut truncated = payload_with_tag(&script, &shielded_tag());
        truncated.truncate(COINBASE_HEAD_LEN + 1 + script.len());
        assert_eq!(truncated.len(), COINBASE_HEAD_LEN + 1 + script.len());
        assert!(!truncated.windows(4).any(|w| w == SHIELDED_TAG_PREFIX), "precondition: the tag is gone");
        assert_eq!(check_private_payment(&coinbase_with_payload(truncated), false, &TEST_GENESIS), Ok(()));
    }
}

