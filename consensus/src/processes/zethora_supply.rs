//! Zethora supply ledger and turnstile (ZTH-SPEC-006 §7.1-7.2).
//!
//! Every chain block carries a ledger of where every zet is, in its coinbase payload:
//!
//! ```text
//! transparent_supply + pool_balance + total_burned + shielded_balance == total_issued
//! ```
//!
//! All values describe the moment after the block's coinbase is counted. Nodes rebuild the ledger
//! from what the block actually did (the real UTXO changes, the rewards it pays, the fee pool step)
//! and reject the block if it does not balance. Two independent counts must agree:
//!   * what the UTXO set really gained or lost (`visible_change`), and
//!   * what the reward and fee rules say should have happened (issued, tips, pool, burn).
//!
//! A bookkeeping bug that creates or loses even one zet makes the ledger unbalanced, and the
//! private pool's public balance (the turnstile) can never go below zero.
//!
//! The hard cap (ZTH-SPEC-001 §5): no block may bring the total ever issued above 100,000,000 ZTHR
//! (`CAP_UNITS`). The reward schedule itself stops ~1,000 ZTHR short of it (see `zethora_subsidy`), so this
//! rule never fires on an honest chain; it is the backstop that keeps the cap even if a future bug or an
//! unforeseen block pattern paid too much: such a block is invalid.

use crate::processes::zethora_subsidy::CAP_UNITS;
use kaspa_consensus_core::coinbase::PoolState;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupplyError {
    /// More value tried to leave the private pool than is inside it.
    ShieldedPoolNegative { balance: u64, value_in: u64, value_out: u64 },
    /// The visible supply would be negative or too large.
    VisibleSupplyOutOfRange(i128),
    /// A running counter would overflow.
    CounterOverflow(&'static str),
    /// The ledger does not add up.
    Unbalanced { transparent: u64, pool: u64, burned: u64, shielded: u64, issued: u64 },
    /// The block would bring the total ever issued above the 100,000,000 ZTHR hard cap.
    CapExceeded { issued: u64 },
}

impl fmt::Display for SupplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SupplyError::ShieldedPoolNegative { balance, value_in, value_out } => {
                write!(f, "private pool would go below zero: balance {balance} + in {value_in} < out {value_out} zets")
            }
            SupplyError::VisibleSupplyOutOfRange(v) => write!(f, "visible supply out of range: {v} zets"),
            SupplyError::CounterOverflow(name) => write!(f, "{name} counter overflow"),
            SupplyError::Unbalanced { transparent, pool, burned, shielded, issued } => write!(
                f,
                "ledger does not balance: visible {transparent} + fee pool {pool} + burned {burned} + private pool {shielded} != issued {issued} zets"
            ),
            SupplyError::CapExceeded { issued } => {
                write!(f, "total issued would be {issued} zets, above the 100,000,000 ZTHR hard cap ({CAP_UNITS} zets)")
            }
        }
    }
}

impl std::error::Error for SupplyError {}

/// The turnstile: a private pool's public balance. More can never leave than went in.
pub fn turnstile(balance: u64, value_in: u64, value_out: u64) -> Result<u64, SupplyError> {
    let available = balance as u128 + value_in as u128;
    if value_out as u128 > available {
        return Err(SupplyError::ShieldedPoolNegative { balance, value_in, value_out });
    }
    u64::try_from(available - value_out as u128).map_err(|_| SupplyError::CounterOverflow("private pool"))
}

/// The turnstile for one transaction (ZTH-SPEC-006 §7.1), applied in consensus merge order. `remaining` is the private
/// pool's public balance after the transactions accepted before this one. If the transaction's private payment would
/// take the pool below zero (or overflow it), returns false and leaves `remaining` unchanged: the transaction is then
/// not accepted, so none of its effects happen. Otherwise applies its pool flows to `remaining` and returns true.
/// Ordinary transactions always pass. A payload whose value balance can't be read never passes (validation refuses it).
pub fn turnstile_accepts(remaining: &mut u64, payload: &[u8]) -> bool {
    match kaspa_consensus_core::zethora_private::pool_flows(payload) {
        Ok(None) => true,
        Ok(Some((value_in, value_out))) => match turnstile(*remaining, value_in, value_out) {
            Ok(next) => {
                *remaining = next;
                true
            }
            Err(_) => false,
        },
        Err(()) => false,
    }
}

/// Everything one chain block changes in the ledger, apart from the fee pool step.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BlockFlows {
    /// New zets created by the block rewards paid in this block's coinbase.
    pub issued: u64,
    /// Fees nobody could be paid (destroyed, so counted as burned).
    pub unpaid: u64,
    /// Net change in visible coins from the transactions this block accepts, measured from the real
    /// UTXO changes (not counting the selected parent's coinbase). With correct bookkeeping this is
    /// minus the total fees.
    pub visible_change: i128,
    /// Total value of this block's coinbase outputs.
    pub coinbase_out: u64,
    /// Value moved into the private pool (0 until private transactions exist).
    pub shielded_in: u64,
    /// Value moved out of the private pool (0 until private transactions exist).
    pub shielded_out: u64,
}

/// Builds this block's ledger and checks that it balances.
///
/// `parent` is the selected parent's ledger. `after_pool` is the fee pool step applied to it
/// (see `zethora_fees::pool_step`), which updates only `pool_balance` and `total_burned`.
pub fn ledger_step(parent: PoolState, after_pool: PoolState, flows: BlockFlows) -> Result<PoolState, SupplyError> {
    let total_burned = after_pool.total_burned.checked_add(flows.unpaid).ok_or(SupplyError::CounterOverflow("total burned"))?;
    let total_issued = parent.total_issued.checked_add(flows.issued).ok_or(SupplyError::CounterOverflow("total issued"))?;
    if total_issued > CAP_UNITS {
        return Err(SupplyError::CapExceeded { issued: total_issued });
    }
    let visible = parent.transparent_supply as i128 + flows.visible_change + flows.coinbase_out as i128;
    let transparent_supply = u64::try_from(visible).map_err(|_| SupplyError::VisibleSupplyOutOfRange(visible))?;
    let shielded_balance = turnstile(parent.shielded_balance, flows.shielded_in, flows.shielded_out)?;
    let next = PoolState { pool_balance: after_pool.pool_balance, total_burned, total_issued, transparent_supply, shielded_balance };
    check_balanced(&next)?;
    Ok(next)
}

/// Checks: visible + fee pool + burned + private pool == issued.
pub fn check_balanced(l: &PoolState) -> Result<(), SupplyError> {
    let held = l.transparent_supply as u128 + l.pool_balance as u128 + l.total_burned as u128 + l.shielded_balance as u128;
    if held == l.total_issued as u128 {
        Ok(())
    } else {
        Err(SupplyError::Unbalanced {
            transparent: l.transparent_supply,
            pool: l.pool_balance,
            burned: l.total_burned,
            shielded: l.shielded_balance,
            issued: l.total_issued,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::processes::zethora_fees::pool_step;

    /// One simulated chain block, built the same way the coinbase builder does it.
    /// Returns the next ledger. `cheat` adds zets out of thin air to the visible change.
    fn simulate_block(
        parent: PoolState,
        subsidy: u64,
        tips: u64,
        base: u64,
        unpaid: u64,
        cheat: i128,
    ) -> Result<PoolState, SupplyError> {
        let pool = pool_step(parent, base);
        let fees = tips + base;
        let coinbase_out = subsidy + (tips - unpaid) + pool.payout;
        let flows =
            BlockFlows { issued: subsidy, unpaid, visible_change: -(fees as i128) + cheat, coinbase_out, ..Default::default() };
        ledger_step(parent, pool.next, flows)
    }

    #[test]
    fn genesis_ledger_balances() {
        assert_eq!(check_balanced(&PoolState::default()), Ok(()));
    }

    #[test]
    fn honest_chain_always_balances() {
        // 20,000 blocks with varied rewards and fees; fees can only be paid from coins that exist.
        let mut ledger = PoolState::default();
        let mut seed: u64 = 0x5eed_2e7a;
        for i in 0..20_000u64 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let subsidy = 2_745_536_136 - (i % 1000);
            let spendable = ledger.transparent_supply;
            let base = (seed >> 20) % 2_000_000 % (spendable / 2 + 1);
            let tips = (seed >> 40) % 500_000 % (spendable / 2 - base.min(spendable / 2) + 1);
            let unpaid = if i % 997 == 0 { tips } else { 0 }; // rare non-DAA blue: its tips are lost
            ledger = simulate_block(ledger, subsidy, tips, base, unpaid, 0).expect("honest block must balance");
        }
        assert!(ledger.pool_balance > 0 && ledger.total_burned > 0);
        assert_eq!(check_balanced(&ledger), Ok(()));
    }

    #[test]
    fn one_counterfeit_zet_is_caught() {
        let ledger = simulate_block(PoolState::default(), 1_000_000, 0, 0, 0, 0).unwrap();
        let err = simulate_block(ledger, 1_000_000, 10_000, 50_000, 0, 1).unwrap_err();
        assert!(matches!(err, SupplyError::Unbalanced { .. }), "got {err:?}");
        // Losing a zet is caught too
        let err = simulate_block(ledger, 1_000_000, 10_000, 50_000, 0, -1).unwrap_err();
        assert!(matches!(err, SupplyError::Unbalanced { .. }), "got {err:?}");
    }

    #[test]
    fn unpaid_tips_count_as_burned() {
        let ledger = simulate_block(PoolState::default(), 1_000_000, 0, 0, 0, 0).unwrap();
        let next = simulate_block(ledger, 0, 7_000, 0, 7_000, 0).unwrap();
        assert_eq!(next.total_burned, ledger.total_burned + 7_000);
    }

    #[test]
    fn turnstile_never_goes_below_zero() {
        assert_eq!(turnstile(0, 100, 100), Ok(0));
        assert_eq!(turnstile(50, 0, 50), Ok(0));
        assert_eq!(turnstile(10, 5, 3), Ok(12));
        assert!(matches!(turnstile(0, 100, 101), Err(SupplyError::ShieldedPoolNegative { .. })));
        assert!(matches!(turnstile(u64::MAX, 1, 0), Err(SupplyError::CounterOverflow(_))));
    }

    #[test]
    fn private_pool_moves_keep_ledger_balanced() {
        let ledger = simulate_block(PoolState::default(), 1_000_000, 0, 0, 0, 0).unwrap();
        // 400,000 visible zets go into the private pool (no fees in this example)
        let flows = BlockFlows { visible_change: -400_000, shielded_in: 400_000, ..Default::default() };
        let inside = ledger_step(ledger, ledger, flows).unwrap();
        assert_eq!(inside.shielded_balance, 400_000);
        // Taking out more than went in is rejected even if the visible side "adds up"
        let flows = BlockFlows { visible_change: 400_001, shielded_out: 400_001, ..Default::default() };
        assert!(matches!(ledger_step(inside, inside, flows), Err(SupplyError::ShieldedPoolNegative { .. })));
    }

    /// A private payment payload with this value balance (positive: leaves the pool; negative: enters it)
    fn payment(value_balance: i64) -> Vec<u8> {
        let mut p = kaspa_consensus_core::zethora_private::PRIVATE_PAYMENT_MAGIC.to_vec();
        p.extend([1u8, 1, 0]); // pool version, one action
        p.extend(vec![0u8; kaspa_consensus_core::zethora_private::ACTION_SIZE]);
        p.push(0); // flags
        p.extend(value_balance.to_le_bytes());
        p
    }

    #[test]
    fn turnstile_accepts_one_transaction_at_a_time() {
        // Positive control: payments that fit are accepted and move the balance by exactly their value balance
        let mut remaining = 50_000;
        assert!(turnstile_accepts(&mut remaining, &payment(1_000)));
        assert_eq!(remaining, 49_000);
        assert!(turnstile_accepts(&mut remaining, &payment(-500)));
        assert_eq!(remaining, 49_500);
        // Taking out exactly what is left is fine
        assert!(turnstile_accepts(&mut remaining, &payment(49_500)));
        assert_eq!(remaining, 0);
        // One zet more than the pool holds is refused and leaves the balance untouched
        let mut remaining = 49_000;
        assert!(!turnstile_accepts(&mut remaining, &payment(49_001)));
        assert_eq!(remaining, 49_000);
        // ... and the next payment that fits is still accepted from the untouched balance
        assert!(turnstile_accepts(&mut remaining, &payment(49_000)));
        assert_eq!(remaining, 0);
        // Ordinary transactions always pass and never move the balance
        assert!(turnstile_accepts(&mut remaining, b"hello"));
        assert!(turnstile_accepts(&mut remaining, &[]));
        assert_eq!(remaining, 0);
        // An unreadable value balance never passes
        let mut remaining = 10;
        assert!(!turnstile_accepts(&mut remaining, b"ZSHP"));
        assert_eq!(remaining, 10);
        // Overflow is refused, not wrapped
        let mut remaining = u64::MAX;
        assert!(!turnstile_accepts(&mut remaining, &payment(-1)));
        assert_eq!(remaining, u64::MAX);
    }

    #[test]
    fn turnstile_order_decides_which_payment_is_accepted() {
        // 50,000 in the pool; two payments each fit alone (1,000 and 49,500) but not together: the first in merge
        // order is accepted, the second is not, and the balance never goes below zero
        let (honest, other) = (payment(1_000), payment(49_500));
        let mut remaining = 50_000;
        let accepted: Vec<bool> = [&honest, &other].iter().map(|p| turnstile_accepts(&mut remaining, p)).collect();
        assert_eq!(accepted, vec![true, false]);
        assert_eq!(remaining, 49_000);
        let mut remaining = 50_000;
        let accepted: Vec<bool> = [&other, &honest].iter().map(|p| turnstile_accepts(&mut remaining, p)).collect();
        assert_eq!(accepted, vec![true, false]);
        assert_eq!(remaining, 500);
        // Value brought in earlier in merge order can be taken out later
        let mut remaining = 0;
        assert!(!turnstile_accepts(&mut remaining, &payment(700)));
        assert!(turnstile_accepts(&mut remaining, &payment(-700)));
        assert!(turnstile_accepts(&mut remaining, &payment(700)));
        assert_eq!(remaining, 0);
    }

    #[test]
    fn issuing_past_the_hard_cap_is_refused() {
        // A ledger with 5 zets left under the cap (kept balanced: everything issued is visible)
        let near = PoolState { total_issued: CAP_UNITS - 5, transparent_supply: CAP_UNITS - 5, ..Default::default() };
        assert_eq!(check_balanced(&near), Ok(()));
        // Issuing exactly up to the cap is fine...
        let ok = BlockFlows { issued: 5, coinbase_out: 5, ..Default::default() };
        assert_eq!(ledger_step(near, near, ok).unwrap().total_issued, CAP_UNITS);
        // ...one zet more is refused, even though the ledger itself would balance
        let over = BlockFlows { issued: 6, coinbase_out: 6, ..Default::default() };
        assert_eq!(ledger_step(near, near, over), Err(SupplyError::CapExceeded { issued: CAP_UNITS + 1 }));
    }

    #[test]
    fn negative_visible_supply_is_rejected() {
        let flows = BlockFlows { visible_change: -1, ..Default::default() };
        let err = ledger_step(PoolState::default(), PoolState::default(), flows).unwrap_err();
        assert_eq!(err, SupplyError::VisibleSupplyOutOfRange(-1));
    }
}

#[cfg(test)]
mod zethora_task4_smoke {
    use super::turnstile;
    use kaspa_consensus_core::zethora_private::private_state_spent_element;

    #[test]
    fn spent_element_is_deterministic_and_distinct() {
        let n1 = [7u8; 32];
        let n2 = [9u8; 32];

        let e1a = private_state_spent_element(&n1);
        let e1b = private_state_spent_element(&n1);
        let e2 = private_state_spent_element(&n2);

        assert_eq!(e1a, e1b, "same nullifier must map to same spent-element");
        assert_ne!(e1a, e2, "different nullifiers must map to different spent-elements");
        assert_eq!(e1a.len(), 33, "spent-element must be 33 bytes (tag + nullifier)");
    }

    #[test]
    fn turnstile_is_sequential_and_rejects_second_debit() {
        let start = 100u64;
        let spend = 60u64;

        let after_a = turnstile(start, 0, spend).expect("first spend should succeed");
        assert_eq!(after_a, 40);

        let after_b = turnstile(after_a, 0, spend);
        assert!(after_b.is_err(), "second sequential spend must underflow");

        let buggy_a = turnstile(start, 0, spend);
        let buggy_b = turnstile(start, 0, spend);
        assert!(buggy_a.is_ok() && buggy_b.is_ok(), "both succeed against parent");
    }
}
