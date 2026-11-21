# Zethora Audit — Persisted Knowledge

> Auto-maintained during the pre-mainnet audit. Read this first in a new session.

## Locked rules
1. **Fix everything, nothing left behind.** Every finding gets a fix + a compile check. No "downgrade to cosmetic / skip."
2. **Save knowledge persistently.** Record facts to this file + memory as we work, not just at the end.

## Build / environment facts
- Repo: C:\Zethora\zethora-node, branch zethora.
- **The user's default C:\Users\admin\.cargo has a corrupted ACL and is unusable.** It cannot be fixed without a true elevated (High-integrity) prompt. Do NOT try to use it.
- **Use CARGO_HOME = C:\Users\admin\.cargo_clean** for every cargo command, e.g.:
  $env:CARGO_HOME = "C:\Users\admin\.cargo_clean"
- Compile check pattern that works (writes log, reports true exit code):
  cmd /c "cargo check -p <crate> --features wallet > "$env:TEMP\check.log" 2>&1" then check $LASTEXITCODE (0 = clean).
- File-read in chat is unreliable; prefer dumping exact line ranges with PowerShell and pasting.

## Repo layout facts
- zethora-shield/src/main.rs — devnet CLI tool (~921 lines). No lib.rs.
- zethora-shielded/layout/src/lib.rs — THE source of truth for private-payment byte layout (80 lines, compile-time asserts).
- zethora-shielded/src/lib.rs — verifier + proof cache + note tree (351 lines).
- zethora-shielded/src/wallet.rs — key derivation + shielding payment (~86 lines).
- zethora-shielded/src/scan.rs — wallet scanner, pick_coins (268 lines).
- orchard: git dep https://github.com/zcash/orchard pinned rev 616a669df8c9a59c33d47064d3ce04b25d026b2e (official Zcash repo).

## Constants / layout
- Coinbase payload: 48..56 shielded balance, 56..88 note root, 88..120 private-state fingerprint. (Confirmed by 5 consensus tests.)
- MAX_ZETS: u64 = CAP_UNITS in consensus/core/src/constants.rs:44. This is the protocol max value; consensus rejects any payment > MAX_ZETS with InputAmountTooHigh (zethora_mint_attacks.rs).
- Forked orchard has MAX_NOTE_VALUE = u64::MAX (from_raw does NOT range-check; caller must). Consensus defends via MAX_ZETS, but the wallet should also guard.
- zethora-shielded does NOT depend on kaspa-consensus-core (only dev-dependency) → CANNOT import MAX_ZETS; must mirror as a local const.

## Work done
### zethora-shield/src/main.rs
- FIXED: faucet no longer panics on largest coin; picks largest coin covering amount+FEE+MIN_CHANGE; clearer errors; submit errors reported. (extra orphan brace removed) — compiles (EXIT 0).
- FIXED: autoshield MIN_CHANGE.max(1) -> MIN_CHANGE.
- FIXED: autoshield mojibake em-dashes -> ASCII.
- FIXED: autoshield hot loop -> 500ms sleep after successful submit.
- CLEARED: bump fee math (was a false alarm; pick_coins is deterministic largest-first, both txs share one coin set).
- CLEARED: seal offsets 56..88 / 88..92 confirmed correct vs consensus tests.
- OPEN (deferred, low priority): attack-1 error-string matching; parse_amount f64 precision; viewkey message wording (FVK reveals full incoming+outgoing history).

### zethora-shielded/layout/src/lib.rs
- CLEAR. Compile-time asserts pin ACTION_SIZE=820, ACTIONS_OFFSET=3, PROOF_OFFSET=45. Overflow-safe offset fns. Correct.

### zethora-shielded/src/lib.rs
- FIXED: verify_payments_batch expect() -> eturn false (no remote panic). Compiles.
- FIXED: doc typo Self::to_bytes] -> ..
- CLEARED: proof-key cache soundness (only successes cached; consensus-neutral); pool_flows; tree size-binding; empty-leaf padding defense; 2^32 capacity test.

### zethora-shielded/src/wallet.rs
- CLEAR on key derivation: from_seed deterministic/one-way with domain tags; friend_of domain-separated; full_viewing_key cannot spend (correct); address Scope::External.
- OPEN FIX (next action): add MAX_NOTE_VALUE guard in shielding_payment (mirror MAX_ZETS as local const; cannot import it), clear error on oversize; document friend_of key-isolation invariant (mainnet friend = separate seed).

## Remaining audit backlog
- zethora-shielded/src/scan.rs: verify root(), add_payment, checkpoint (pick_coins done, clear).
- zethora-shielded/src/codec.rs: encode/decode round-trip vs layout.
- zethora-shielded/orchard/ vendored? (it's a git dep, not vendored).
- zethora-miner, daemon, bridge, zethora-dex, daemon, cli.
- Whole workspace clippy pass (not yet run).

## Unrecorded (need input)
- "Website" changes from a previous chat — NOT recorded, unknown.
- "JB VPS" — NOT recorded, unknown.

_Last updated: see file mtime._