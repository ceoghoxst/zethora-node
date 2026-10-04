//! Minimal wallet side for the devnet: a private address and "shield coins into the private pool".

use crate::{CIRCUIT, SupportedPool, codec, sighash};
use incrementalmerkletree::Hashable;
use orchard::{
    Address,
    builder::{Builder, BundleType},
    bundle::{BundleVersion, Flags, TxVersion},
    circuit::ProvingKey,
    keys::{FullViewingKey, Scope, SpendingKey},
    tree::MerkleHashOrchard,
    value::NoteValue,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use std::sync::OnceLock;

/// The proving key for making private payments, built once (a few seconds) on first use.
pub fn proving_key() -> &'static ProvingKey {
    static PK: OnceLock<ProvingKey> = OnceLock::new();
    PK.get_or_init(|| ProvingKey::build(CIRCUIT))
}

/// A private wallet derived from a 32-byte seed (devnet: the miner's key file).
pub struct PrivateWallet {
    sk: SpendingKey,
}

impl PrivateWallet {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        // Not every 32-byte string is a valid Orchard spending key, so hash with a counter until one is.
        for counter in 0u32.. {
            let candidate = blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"ZethoraOrchardSK")
                .to_state()
                .update(seed)
                .update(&counter.to_le_bytes())
                .finalize();
            let bytes: [u8; 32] = candidate.as_bytes().try_into().expect("32-byte hash");
            if let Some(sk) = Option::<SpendingKey>::from(SpendingKey::from_bytes(bytes)) {
                return Self { sk };
            }
        }
        unreachable!("a valid key is found within a few tries")
    }

    pub fn full_viewing_key(&self) -> FullViewingKey {
        FullViewingKey::from(&self.sk)
    }

    /// This wallet's private address.
    pub fn address(&self) -> Address {
        self.full_viewing_key().address_at(0u32, Scope::External)
    }
}

/// Builds an encoded private payment that moves `value` zets into the private pool, paying the new
/// private coin to `to`. `tx_digest` is the digest of the Zethora transaction that will carry it.
/// Spending is switched off on the network for now, so this payment has spends disabled.
pub fn shielding_payment(to: Address, value: u64, tx_digest: &[u8; 32]) -> Result<Vec<u8>, String> {
    #[allow(non_upper_case_globals)]
    const OsRng: UnwrapErr<SysRng> = UnwrapErr(SysRng);
    let mut rng = OsRng;

    let empty_anchor = MerkleHashOrchard::empty_root(32.into()).into();
    let mut builder = Builder::new(BundleType::DEFAULT, BundleVersion::orchard_v2(), Flags::SPENDS_DISABLED, empty_anchor)
        .map_err(|e| format!("builder: {e:?}"))?;
    builder.add_output(None, to, NoteValue::from_raw(value), [0u8; 512]).map_err(|e| format!("output: {e:?}"))?;
    let (unauthorized, _) =
        builder.build::<i64>(&mut rng).map_err(|e| format!("build: {e:?}"))?.ok_or_else(|| "empty payment".to_string())?;
    let commitment = unauthorized.commitment(TxVersion::V5).map_err(|e| format!("commitment: {e:?}"))?;
    let sighash = sighash(tx_digest, commitment.into());
    let bundle = unauthorized
        .create_proof(proving_key(), &mut rng)
        .map_err(|e| format!("proof: {e:?}"))?
        .apply_signatures(rng, sighash, &[])
        .map_err(|e| format!("signatures: {e:?}"))?;
    Ok(codec::encode(&bundle, SupportedPool::Orchard1))
}
