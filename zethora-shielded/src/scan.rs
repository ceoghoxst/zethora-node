//! Wallet side of private spends (devnet tools, ZTH-SPEC-006): find your private coins on the chain, keep proof that
//! they are in the coin list, and build payments that spend them.
//!
//! The scanner must see every private payment the chain accepted, in consensus order (chain block by chain block,
//! then mergeset order, then transaction order). It rebuilds the same private coin list the nodes keep, so its root
//! can be checked against the root sealed in every coinbase.
//!
//! Spends prove membership in a snapshot of the coin list (the anchor). The network only accepts snapshots buried at
//! least `ANCHOR_DEPTH` blocks deep, so the scanner takes its snapshot (`checkpoint`) at the last chain block that is
//! deep enough, and keeps reading after it only to learn which coins were spent since.

use crate::{
    NoteCommitmentTree, SupportedPool, codec, sighash,
    wallet::{PrivateWallet, proving_key},
};
use incrementalmerkletree::{Position, Retention};
use orchard::{
    Address, Anchor, Note,
    builder::{Builder, BundleType},
    bundle::{BundleVersion, TxVersion},
    keys::{IncomingViewingKey, Scope, SpendAuthorizingKey},
    note::ExtractedNoteCommitment,
    tree::{MerkleHashOrchard, MerklePath},
    value::NoteValue,
};
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use std::collections::HashSet;

/// The one snapshot the scanner keeps: the coin list as of the last deep-enough chain block.
const SNAPSHOT: u32 = 0;

/// A private coin that belongs to one of the scanned wallets.
#[derive(Clone, Debug)]
pub struct OwnedCoin {
    /// Which wallet (index into the list given to `Scanner::new`)
    pub wallet: usize,
    pub note: Note,
    /// Position in the coin list
    pub position: u64,
    /// The tag that spending this coin reveals
    pub nullifier: [u8; 32],
}

impl OwnedCoin {
    pub fn value(&self) -> u64 {
        self.note.value().inner()
    }
}

/// Coins of one wallet, as seen by the scanner.
#[derive(Clone, Debug, Default)]
pub struct Holdings {
    /// Unspent and deep enough to spend now
    pub spendable: Vec<OwnedCoin>,
    /// Unspent but received after the snapshot: spendable in about 10 minutes
    pub maturing: Vec<OwnedCoin>,
}

impl Holdings {
    pub fn spendable_total(&self) -> u64 {
        self.spendable.iter().map(OwnedCoin::value).sum()
    }
    pub fn maturing_total(&self) -> u64 {
        self.maturing.iter().map(OwnedCoin::value).sum()
    }
}

pub struct Scanner {
    wallets: Vec<(PrivateWallet, IncomingViewingKey)>,
    /// Full coin list with proofs kept for our own coins
    tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16>,
    /// Same list as the nodes keep it (frontier only), used to check our roots against the chain's
    frontier: NoteCommitmentTree,
    coins: Vec<OwnedCoin>,
    spent: HashSet<[u8; 32]>,
    /// Coin list size when the snapshot was taken (None until `checkpoint`)
    snapshot_size: Option<u64>,
}

impl Scanner {
    pub fn new(wallets: Vec<PrivateWallet>) -> Self {
        let wallets = wallets
            .into_iter()
            .map(|w| {
                let ivk = w.full_viewing_key().to_ivk(Scope::External);
                (w, ivk)
            })
            .collect();
        Self {
            wallets,
            tree: ShardTree::new(MemoryShardStore::empty(), 10),
            frontier: NoteCommitmentTree::new(),
            coins: Vec::new(),
            spent: HashSet::new(),
            snapshot_size: None,
        }
    }

    /// The coin list root so far, exactly as nodes compute it (to compare with the root sealed in coinbases).
    pub fn root(&self) -> [u8; 32] {
        self.frontier.root().to_bytes()
    }

    /// Number of private coins ever created so far.
    pub fn size(&self) -> u64 {
        self.frontier.size()
    }

    /// Reads one accepted private payment (encoded, without the "ZSHP" marker), in consensus order.
    pub fn add_payment(&mut self, encoded: &[u8]) -> Result<(), String> {
        let (bundle, _pool) = codec::decode(encoded).map_err(|e| format!("bad private payment on chain: {e}"))?;
        for (index, action) in bundle.actions().iter().enumerate() {
            self.spent.insert(action.nullifier().to_bytes());

            let cmx: ExtractedNoteCommitment = *action.cmx();
            // Trial-decrypt with each wallet's viewing key (the bundle picks the right note format for its version)
            let mut mine = None;
            for (i, (wallet, ivk)) in self.wallets.iter().enumerate() {
                if let Some((note, _, _)) = bundle.decrypt_output_with_key(index, ivk) {
                    mine = Some((i, note, note.nullifier(&wallet.full_viewing_key()).to_bytes()));
                    break;
                }
            }
            let position = self.frontier.size();
            self.frontier.append(&cmx).map_err(|_| "private coin list is full".to_string())?;
            let retention = if mine.is_some() { Retention::Marked } else { Retention::Ephemeral };
            self.tree.append(MerkleHashOrchard::from_cmx(&cmx), retention).map_err(|e| format!("coin list: {e:?}"))?;
            if let Some((wallet, note, nullifier)) = mine {
                self.coins.push(OwnedCoin { wallet, note, position, nullifier });
            }
        }
        Ok(())
    }

    /// Takes the snapshot spends will prove against. Call once, right after the last chain block that is at least
    /// `ANCHOR_DEPTH` (plus a safety margin) blocks below the tip.
    pub fn checkpoint(&mut self) -> Result<(), String> {
        if self.snapshot_size.is_some() {
            return Err("snapshot already taken".to_string());
        }
        self.tree.checkpoint(SNAPSHOT).map_err(|e| format!("snapshot: {e:?}"))?;
        self.snapshot_size = Some(self.frontier.size());
        Ok(())
    }

    /// The snapshot's root: the anchor spends must use.
    pub fn anchor(&self) -> Result<Anchor, String> {
        let root = self
            .tree
            .root_at_checkpoint_id(&SNAPSHOT)
            .map_err(|e| format!("snapshot root: {e:?}"))?
            .ok_or_else(|| "no snapshot taken yet".to_string())?;
        Ok(root.into())
    }

    /// What one wallet owns.
    pub fn holdings(&self, wallet: usize) -> Holdings {
        let snapshot = self.snapshot_size.unwrap_or(0);
        let mut h = Holdings::default();
        for c in self.coins.iter().filter(|c| c.wallet == wallet && !self.spent.contains(&c.nullifier)) {
            if c.position < snapshot { h.spendable.push(c.clone()) } else { h.maturing.push(c.clone()) }
        }
        h
    }

    fn witness(&self, coin: &OwnedCoin) -> Result<MerklePath, String> {
        let path = self
            .tree
            .witness_at_checkpoint_id(Position::from(coin.position), &SNAPSHOT)
            .map_err(|e| format!("coin proof: {e:?}"))?
            .ok_or_else(|| "no snapshot taken yet".to_string())?;
        Ok(path.into())
    }

    /// Picks spendable coins of `wallet` worth at least `amount` zets (largest first).
    pub fn pick_coins(&self, wallet: usize, amount: u64) -> Result<Vec<OwnedCoin>, String> {
        let mut coins = self.holdings(wallet).spendable;
        coins.sort_by_key(|c| std::cmp::Reverse(c.value()));
        let mut picked = Vec::new();
        let mut total = 0u64;
        for c in coins {
            if total >= amount {
                break;
            }
            total += c.value();
            picked.push(c);
        }
        if total < amount {
            return Err(format!(
                "not enough spendable private coins: have {} zets ready, need {amount} (coins received in the last ~10 minutes can't be spent yet)",
                total
            ));
        }
        if picked.len() > codec::MAX_ACTIONS_PER_TX {
            return Err(format!("would need {} private coins in one payment (max {})", picked.len(), codec::MAX_ACTIONS_PER_TX));
        }
        Ok(picked)
    }

    /// Builds an encoded private payment (without the "ZSHP" marker) spending `coins` of wallet `wallet`.
    /// `outputs` are new private coins; whatever is left over (inputs minus outputs) leaves the private pool into the
    /// visible part of the transaction (`unshield`), so pass a change output back to yourself to keep it private.
    /// `tx_digest` is the digest of the Zethora transaction that will carry it.
    pub fn spend_payment(
        &self,
        wallet: usize,
        coins: &[OwnedCoin],
        outputs: &[(Address, u64)],
        tx_digest: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        spend_payment_with(&self.wallets[wallet].0, coins.iter().map(|c| Ok((c.note, self.witness(c)?))), self.anchor()?, outputs, tx_digest)
    }
}

/// Builds a spend from explicit coins and their proofs against `anchor` (also used to build deliberately bad
/// payments in attack tests).
pub fn spend_payment_with(
    wallet: &PrivateWallet,
    coins: impl IntoIterator<Item = Result<(Note, MerklePath), String>>,
    anchor: Anchor,
    outputs: &[(Address, u64)],
    tx_digest: &[u8; 32],
) -> Result<Vec<u8>, String> {
    #[allow(non_upper_case_globals)]
    const OsRng: UnwrapErr<SysRng> = UnwrapErr(SysRng);
    let mut rng = OsRng;

    let fvk = wallet.full_viewing_key();
    let version = BundleVersion::orchard_v2();
    let mut builder =
        Builder::new(BundleType::DEFAULT, version, version.default_flags(), anchor).map_err(|e| format!("builder: {e:?}"))?;
    for coin in coins {
        let (note, path) = coin?;
        builder.add_spend(fvk.clone(), note, path).map_err(|e| format!("spend: {e:?}"))?;
    }
    let ovk = Some(fvk.to_ovk(Scope::External));
    for (to, value) in outputs {
        builder.add_output(ovk.clone(), *to, NoteValue::from_raw(*value), [0u8; 512]).map_err(|e| format!("output: {e:?}"))?;
    }
    let (unauthorized, _) =
        builder.build::<i64>(&mut rng).map_err(|e| format!("build: {e:?}"))?.ok_or_else(|| "empty payment".to_string())?;
    let commitment = unauthorized.commitment(TxVersion::V5).map_err(|e| format!("commitment: {e:?}"))?;
    let sighash = sighash(tx_digest, commitment.into());
    let bundle = unauthorized
        .create_proof(proving_key(), &mut rng)
        .map_err(|e| format!("proof: {e:?}"))?
        .apply_signatures(rng, sighash, &[SpendAuthorizingKey::from(wallet.spending_key())])
        .map_err(|e| format!("signatures: {e:?}"))?;
    Ok(codec::encode(&bundle, SupportedPool::Orchard1))
}
