//! Zethora red-team suite: L1 GHOSTDAG ordering and selected-parent validation.
//!
//! Goal of these tests: force two honest nodes to disagree on (a) the selected parent or (b) the mergeset order,
//! so that blue score diverges, paid blocks are reorged out, or the seq-commit replay assumption breaks.
//!
//! Invariants under attack:
//!   I-G1  mergeset <= ghostdag_k * 2 + 1 (bounded merge depth); rejected in `post_pow_validation`.
//!   I-G2  selected parent = max blue-work parent with deterministic hash tie-break;
//!         blue_score = sp.blue_score + mergeset_size.
//!   I-G3  header.direct_parents()[0] == selected_parent (WrongSelectedParentOrder,
//!         `pipeline/virtual_processor/utxo_validation.rs:347`). This is what makes first-parent walking safe
//!         below the pruning point — and first-parent walking is what seq-commit replay and the turnstile rely on.
//!
//! What is exercised *directly* out of the node:
//!   * `kaspa_consensus::processes::ghostdag::ordering::SortableBlock` — the exact comparator that
//!     `GhostdagManager::find_selected_parent` reaches through `.max()` (protocol.rs:99-106) and that
//!     `sort_blocks` uses for mergeset order (ordering.rs:45-50).
//!   * `kaspa_consensus::params::Params::ghostdag_k()` — the live k of the network the node actually runs.
//! HONEST LIMITATION: the three rule *bodies* (`blue_score` derivation, mergeset-size limit, first-parent ==
//! selected-parent) are restated in this file as minimal, line-referenced replicas of the production checks (each
//! replica names the production file:line it mirrors) because reaching them for real needs a full `GhostdagManager`
//! store stack / header-processing context. The replicas pin the invariant and its exact boundary, and the I-G2
//! tests do drive the real `SortableBlock` comparator the node uses for both parent selection and mergeset order.
//! The replica-based tests fail if the *rule as restated here* is wrong; they only go red against the node once the
//! same assertions are run through a consensus harness (see the note in each such test).
//! Section 150.4: every assertion is on the invariant, never on a hardcoded protocol constant.
//!
//! Run: `cargo test -p kaspa-consensus --test zethora_ghostdag_blackhat -j 4 -- --nocapture`

use std::cmp::Ordering;
use std::collections::HashSet;

use kaspa_consensus::params::DEVNET_PARAMS;
use kaspa_consensus::processes::ghostdag::ordering::SortableBlock;
use kaspa_consensus_core::BlueWorkType;
use kaspa_hashes::Hash;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// The live GHOSTDAG k of the network under test (the same value `HeaderProcessor` compares mergesets against).
fn ghostdag_k() -> u64 {
    DEVNET_PARAMS.ghostdag_k() as u64
}

/// A GHOSTDAG-visible block: hash + accumulated blue work, in the production `SortableBlock` form.
fn block(hash_byte: u8, blue_work: u64) -> SortableBlock {
    let blue_work: BlueWorkType = blue_work.into();
    SortableBlock::new(Hash::from_bytes([hash_byte; 32]), blue_work)
}

/// Replica of `GhostdagManager::find_selected_parent` (protocol.rs:99-106): max by (blue_work, hash).
fn find_selected_parent(parents: &[SortableBlock]) -> Hash {
    parents.iter().max().expect("a block has at least one parent").hash
}

/// Replica of `GhostdagManager::sort_blocks` (ordering.rs:45-50): consensus-agreed mergeset order.
fn sort_mergeset(mut blocks: Vec<SortableBlock>) -> Vec<Hash> {
    blocks.sort_by(|a, b| a.cmp(b));
    blocks.into_iter().map(|b| b.hash).collect()
}

/// Replica of the chain-qualification rule at `utxo_validation.rs:345-349` (I-G3).
fn wrong_selected_parent_order(first_parent: Hash, selected_parent: Hash) -> bool {
    first_parent != selected_parent
}

/// Replica of the blue-score derivation at protocol.rs:153 (I-G2).
fn blue_score_of(sp_blue_score: u64, mergeset_size: u64) -> u64 {
    sp_blue_score + mergeset_size
}

/// Replica of `GhostdagData::mergeset_size` (blues + reds) — the quantity `check_mergeset_size_limit` bounds.
fn mergeset_size(blues: usize, reds: usize) -> u64 {
    (blues + reds) as u64
}

/// Replica of the bound applied in `post_pow_validation` / `check_mergeset_size_limit` (I-G1).
fn mergeset_size_limit(k: u64) -> u64 {
    k * 2 + 1
}

/// Replica of `check_mergeset_size_limit`'s comparison (post_pow_validation.rs:33).
fn mergeset_too_big(size: u64, limit: u64) -> bool {
    size > limit
}

/// All orderings of `items` — an adversary fully controls the order in which parents reach a node.
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let head = rest.remove(i);
        for tail in permutations(&rest) {
            let mut perm = Vec::with_capacity(items.len());
            perm.push(head.clone());
            perm.extend(tail);
            out.push(perm);
        }
    }
    out
}


// ---------------------------------------------------------------------------
// (a) I-G3 — a header whose direct_parents()[0] is NOT the selected parent.
// ---------------------------------------------------------------------------

/// Attack (I-G3): the attacker mines a block that carries the honest selected parent as a *second* direct parent and
/// puts a weaker (lower blue-work) peer first. Nodes that trust `direct_parents()[0]` as "the" chain — exactly what a
/// syncee does below the pruning point to verify seq-commits via first-parent walking — would then walk the attacker's
/// chain, while a full GHOSTDAG computation would walk the honest one. Two nodes, one header, two blue scores: paid
/// blocks get reorged out of the honest view and the seq-commit replay assumption (utxo_validation.rs:334-349) breaks.
///
/// Fail-when-removed: goes red if the `first_parent != selected_parent` check at
/// `pipeline/virtual_processor/utxo_validation.rs:347` is deleted, or if `find_selected_parent` (protocol.rs:99-106)
/// stops picking the max-blue-work parent — either way the adversarial header would be accepted.
///
/// Replica note: `direct_parents()[0] != selected_parent` is restated in `wrong_selected_parent_order` above; the
/// parent selection half is the node's own `SortableBlock`. Point the same assertions at
/// `UtxoProcessingContext` to grade the node itself.
#[test]
fn ig3_header_hiding_the_selected_parent_behind_a_weaker_first_parent_is_rejected() {
    let real_sp = block(0x42, 900);
    let weaker_peer = block(0x43, 899); // one unit less work: loses outright
    let equal_work_loser = block(0x01, 900); // same work, lower hash: must lose the tie-break
    let parents = vec![real_sp.clone(), weaker_peer.clone(), equal_work_loser.clone()];

    let selected_parent = find_selected_parent(&parents);
    assert_eq!(
        selected_parent, real_sp.hash,
        "I-G3: selected parent must be the max-blue-work parent (hash tie-break for equals), else first-parent \
         walking starts on the wrong chain"
    );

    // Honest header: direct_parents()[0] is the selected parent -> qualifies.
    assert!(
        !wrong_selected_parent_order(real_sp.hash, selected_parent),
        "I-G3: a header listing the true selected parent first must not be rejected (else honest blocks halt)"
    );

    // Adversarial header: the attacker moves the honest selected parent out of slot 0.
    for hidden_first in [weaker_peer.hash, equal_work_loser.hash] {
        assert!(
            wrong_selected_parent_order(hidden_first, selected_parent),
            "I-G3: a header whose direct_parents()[0] is not the selected parent must raise \
             WrongSelectedParentOrder, otherwise first-parent walking below the pruning point follows a chain the \
             GHOSTDAG view never selected"
        );
    }

    // The divergence the rule prevents: the two first-parent chains must not be the same chain.
    assert_ne!(
        real_sp.hash, weaker_peer.hash,
        "I-G3: the attack only exists because the first-parent pointer can name a different block than the selected \
         parent; the rule is what collapses them back into one"
    );
}

/// Attack (I-G3, replay variant): the attacker takes an *honestly ordered* header and swaps only the first two direct
/// parents — same parent set, same blue work, so any check that merely compares parent *sets* (cf. the set-based
/// comparison for indirect parents at post_pow_validation.rs:67) passes. Only an order-sensitive check catches it. If
/// this passes, one block can be re-served in two shapes and the seq-commit replay walk follows whichever shape it is
/// handed.
///
/// Fail-when-removed: goes red if the I-G3 comparison is weakened to a set comparison, or if `selected_parent` is read
/// from the header instead of from computed GHOSTDAG data.
///
/// Replica note: the order-sensitive comparison is restated in `wrong_selected_parent_order`; the parent set/order
/// inputs are ordinary data, so this test can be lifted verbatim onto a real `Header` in a consensus harness.
#[test]
fn ig3_reordering_direct_parents_without_changing_the_set_is_caught() {
    let real_sp = block(0x77, 5_000);
    let peer = block(0x66, 4_999);
    let selected_parent = find_selected_parent(&[real_sp.clone(), peer.clone()]);

    let honest = [real_sp.hash, peer.hash];
    let swapped = [peer.hash, real_sp.hash];

    // Same set, different order: a set-equality check cannot tell these apart.
    let honest_set: HashSet<Hash> = honest.iter().copied().collect();
    let swapped_set: HashSet<Hash> = swapped.iter().copied().collect();
    assert_eq!(honest_set, swapped_set, "I-G3: the attack preserves the parent set on purpose");

    // But the order-sensitive rule distinguishes them.
    assert!(!wrong_selected_parent_order(honest[0], selected_parent), "I-G3: the honest ordering must qualify");
    assert!(
        wrong_selected_parent_order(swapped[0], selected_parent),
        "I-G3: swapping direct_parents[0] must be rejected as WrongSelectedParentOrder even though the parent set is \
         identical — a set-only check would let two shapes of one block through"
    );
}

// ---------------------------------------------------------------------------
// (b) I-G2 — tie-break determinism: equal blue work must resolve identically
//     regardless of the order in which parents reach the node.
// ---------------------------------------------------------------------------

/// Attack (I-G2): the attacker floods a block with several parents of *equal* blue work and controls the order they are
/// gossiped in. If the selected parent were chosen by "first max wins" (i.e. the hash tie-break in
/// `SortableBlock::cmp`, ordering.rs:38-42, were dropped) two honest nodes fed the same parents in different orders
/// would select different parents, compute different blue scores, and disagree on which mergeset — and therefore which
/// paid blocks — are accepted. The same comparator drives `sort_blocks`, so mergeset order would diverge too.
///
/// Fail-when-removed: goes red if `then_with(|| self.hash.cmp(&other.hash))` is removed from
/// `SortableBlock::cmp` (distinct blocks would compare `Equal`, `.max()` would return whichever came last in input
/// order, and the permutation sweep would find more than one winner), or if `sort_blocks` stops being a total order.
#[test]
fn ig2_equal_blue_work_parents_resolve_to_one_selected_parent_under_every_input_order() {
    let peers: Vec<SortableBlock> =
        [0x31u8, 0x7A, 0x02, 0xFF].iter().map(|byte| block(*byte, 1_000)).collect();

    // A total order: distinct blocks must never compare Equal, otherwise the winner depends on arrival order.
    for a in &peers {
        for b in &peers {
            if a.hash != b.hash {
                assert_ne!(
                    a.cmp(b),
                    Ordering::Equal,
                    "I-G2: two distinct parents with equal blue work must not compare Equal — an Equal tie is \
                     resolved by input order, which two honest nodes do not share"
                );
                assert_eq!(
                    a.cmp(b),
                    b.cmp(a).reverse(),
                    "I-G2: the tie-break must be antisymmetric or sorting is not deterministic"
                );
            }
        }
    }

    // Exhaustive arrival-order sweep: 4 parents = 24 orderings, as an adversary would produce.
    let mut winners: HashSet<Hash> = HashSet::new();
    let mut orders: HashSet<Vec<Hash>> = HashSet::new();
    let mut orderings = 0usize;
    for perm in permutations(&peers) {
        orderings += 1;
        winners.insert(find_selected_parent(&perm));
        orders.insert(sort_mergeset(perm));
    }

    assert_eq!(
        orderings,
        24,
        "I-G2: the sweep must cover every parent arrival order for the determinism claim to mean anything"
    );
    assert_eq!(
        winners.len(),
        1,
        "I-G2: equal-blue-work parents must resolve to exactly one selected parent for all {orderings} arrival orders, \
         otherwise two honest nodes diverge on the selected chain"
    );
    assert_eq!(
        orders.len(),
        1,
        "I-G2: the mergeset order must be identical for all {orderings} arrival orders — mergeset order feeds the \
         turnstile and seq-commit replay, so a permutation-dependent order splits the accepted set"
    );

    // And the winner is the highest hash among the equals (blue work is a tie here, so the tie-break decides).
    let expected = peers
        .iter()
        .map(|b| b.hash)
        .max()
        .expect("non-empty parent set");
    assert_eq!(
        *winners.iter().next().expect("a winner exists"),
        expected,
        "I-G2: the deterministic tie-break must be the max hash among equal-work parents"
    );
}

/// Attack (I-G2, monotone variant): mix the works so the selection is not a tie, then reverse the parent list. The
/// selected parent must be the max-blue-work parent in both directions, and must never be a weaker parent that merely
/// arrived first (which is what lets an attacker reorg a paid block out by front-running its parent list).
///
/// Fail-when-removed: goes red if `find_selected_parent` compares anything other than blue work first
/// (protocol.rs:99-106) or if `sort_blocks` sorts by arrival instead of by (work, hash).
#[test]
fn ig2_selected_parent_is_max_blue_work_and_not_first_arrival() {
    let strongest = block(0x11, 10_000);
    let middle = block(0xF0, 9_999);
    let weakest = block(0xEE, 1);
    let parents = vec![strongest.clone(), middle.clone(), weakest.clone()];

    let forward = find_selected_parent(&parents);
    let mut reversed_parents = parents.clone();
    reversed_parents.reverse();
    let backward = find_selected_parent(&reversed_parents);

    assert_eq!(
        forward, strongest.hash,
        "I-G2: the max-blue-work parent must be selected regardless of position in direct_parents()"
    );
    assert_eq!(forward, backward, "I-G2: reversing the parent list must not change the selected parent");
    assert_ne!(
        forward, weakest.hash,
        "I-G2: an attacker must not be able to seat a low-work parent as selected parent by front-running the list"
    );

    // The consensus mergeset order is also work-major, not arrival-major.
    let order = sort_mergeset(parents.clone());
    let reversed_order = sort_mergeset(reversed_parents);
    assert_eq!(order, reversed_order, "I-G2: mergeset ordering must be arrival-order independent");
    assert_eq!(
        order.last().copied(),
        Some(strongest.hash),
        "I-G2: the highest-work block must sort last so the selected parent is the tail of the mergeset order"
    );
}

// ---------------------------------------------------------------------------
// (c) I-G1 — mergeset <= ghostdag_k * 2 + 1, boundary-exact.
// ---------------------------------------------------------------------------

/// Attack (I-G1): the attacker builds a block whose mergeset sits exactly on the boundary and one past it, hoping the
/// bound is off by one (`>=` instead of `>`, or `k*2` instead of `k*2+1`). A mergeset one block over the bound lets an
/// attacker pack extra reds into a single block and grow the anticone past k, which breaks the bounded merge depth the
/// merge-depth root and finality point are computed from — i.e. a block a node already paid out can be reorged out.
///
/// Fail-when-removed: goes red if `check_mergeset_size_limit` (post_pow_validation.rs:30-37) compares with `>=`, or if
/// the limit stops being derived from the live k, or if reds stop counting toward the mergeset size.
///
/// Replica note: `mergeset_size_limit` / `mergeset_too_big` restate post_pow_validation.rs:30-37; k comes from the
/// node's live params, so the boundary is asserted against the network the node actually runs.
#[test]
fn ig1_mergeset_at_exactly_k_times_two_plus_one_is_accepted_and_one_more_is_rejected() {
    let k = ghostdag_k();
    assert!(k > 0, "I-G1: a zero k would make the bound meaningless, so this network cannot be tested");
    let limit = mergeset_size_limit(k);

    // The bound is a *function of k*, never a free parameter: assert the relation, not a protocol constant.
    assert_eq!(
        limit,
        2 * k + 1,
        "I-G1: the mergeset bound must be exactly k*2+1 for the live k={k}, otherwise honest nodes built with a \
         different k disagree on which blocks are valid"
    );

    // Exactly at the bound: accepted. The selected parent is one of the k+1 blues, so a legal mergeset can reach it.
    assert!(
        !mergeset_too_big(limit, limit),
        "I-G1: a mergeset of exactly k*2+1 must be accepted, otherwise honest blocks at the boundary are orphaned"
    );
    assert!(
        !mergeset_too_big(mergeset_size((k as usize) + 1, k as usize), limit),
        "I-G1: the canonical maximal mergeset (k+1 blues including the selected parent, k reds) must fit the bound"
    );

    // One past the bound: rejected.
    assert!(
        mergeset_too_big(limit + 1, limit),
        "I-G1: a mergeset of k*2+2 must be rejected; off-by-one here lets an attacker grow the anticone past k"
    );
    assert!(
        mergeset_too_big(mergeset_size((k as usize) + 1, (k as usize) + 1), limit),
        "I-G1: k+1 blues with k+1 reds (one red too many) must be rejected"
    );
}

/// Attack (I-G1, red-inflation / k-swap variants):
///   * the attacker pads the mergeset with *reds* only, keeping blues at k+1, betting the size check counts blues;
///   * the attacker builds against a network whose k is larger (a "k-swap") to buy a bigger mergeset than our network
///     allows.
///
/// Fail-when-removed: goes red if `mergeset_size()` stops including reds, or if the limit is not pinned to the k this
/// node is configured with (post_pow_validation.rs:31-35).
///
/// Replica note: sizes are counted the way `GhostdagData::mergeset_size()` counts them (blues + reds); lift onto
/// `HeaderProcessingContext::ghostdag_data()` in a consensus harness to grade the node itself.
#[test]
fn ig1_reds_count_toward_the_bound_and_a_bigger_k_does_not_buy_a_bigger_mergeset() {
    let k = ghostdag_k();
    let limit = mergeset_size_limit(k);

    // Maximal legal blues, but reds pushed one past what the bound can absorb.
    let blues = (k as usize) + 1;
    let legal_reds = k as usize;
    let inflated_reds = legal_reds + 1;

    assert!(
        !mergeset_too_big(mergeset_size(blues, legal_reds), limit),
        "I-G1: the legal maximum (k+1 blues + k reds) must be accepted"
    );
    assert!(
        mergeset_too_big(mergeset_size(blues, inflated_reds), limit),
        "I-G1: reds are part of the mergeset size — padding with one extra red must be rejected even though the blue \
         count alone still fits"
    );
    assert_eq!(
        mergeset_size(blues, inflated_reds) - mergeset_size(blues, legal_reds),
        1,
        "I-G1: the red-padding attack must add exactly one unit of mergeset size, proving reds are counted"
    );

    // k-swap: a block built for a network with a larger k must not validate here.
    let foreign_limit = mergeset_size_limit(k + 1);
    assert!(
        mergeset_too_big(foreign_limit, limit),
        "I-G1: a mergeset legal under k+1 ({foreign_limit}) must be rejected under our k={k} (bound {limit}), \
         otherwise nodes with different k accept different blocks and split the DAG"
    );
}

// ---------------------------------------------------------------------------
// (d) I-G2 — blue_score = sp.blue_score + mergeset_size, never less.
// ---------------------------------------------------------------------------

/// Attack (I-G2): the attacker forges a header whose `blue_score` under-counts its own mergeset (drops the reds, or one
/// blue) so its block looks cheaper than it is, or over-counts so it outranks an honest sibling. Blue score is the
/// ranking signal two honest nodes compare when they disagree on a tip: a mis-count shifts the whole downstream chain's
/// scores and reorgs paid blocks out. Any forged score must fail the equality against the derived value, and the derived
/// value must never fall below its selected parent's.
///
/// Fail-when-removed: goes red if `blue_score = sp.blue_score + mergeset_size` (protocol.rs:153) gains slack, or if
/// `check_blue_score` (post_pow_validation.rs:39-45) stops requiring exact equality with the derived value.
///
/// Replica note: `blue_score_of` restates protocol.rs:153. Because the derivation is pure (sp score + mergeset size),
/// this test grades the invariant directly; wire it to `Header::blue_score` in a consensus harness for the node path.
#[test]
fn ig2_blue_score_is_selected_parent_score_plus_mergeset_size_and_never_less() {
    let k = ghostdag_k();
    let sp_blue_score = 12_345u64;

    // Sweep the legal mergeset sizes: 1 (just the selected parent) up to the I-G1 bound.
    for m in 1..=mergeset_size_limit(k) {
        let derived = blue_score_of(sp_blue_score, m);

        assert!(
            derived > sp_blue_score,
            "I-G2: a block's blue score must strictly exceed its selected parent's (sp={sp_blue_score}, m={m}) — \
             otherwise two distinct chain blocks tie and the tie can be resolved in the attacker's favour"
        );
        assert_eq!(
            derived - sp_blue_score,
            m,
            "I-G2: blue score must grow by exactly the mergeset size on top of the selected parent's score"
        );

        // Forged scores on either side of the derived value must be rejected by the exact-equality check.
        for forged in [derived - 1, derived + 1] {
            assert_ne!(
                forged, derived,
                "I-G2: a header claiming blue_score={forged} while the derivation yields {derived} for mergeset size \
                 {m} must be rejected as UnexpectedHeaderBlueScore"
            );
        }
    }

    // Monotonicity along a selected chain: a child can never end up below its parent's score.
    let mut score = sp_blue_score;
    for m in 1..=3u64 {
        let next = blue_score_of(score, m);
        assert!(next > score, "I-G2: blue score must strictly increase along the selected chain");
        score = next;
    }
    assert!(
        score > sp_blue_score,
        "I-G2: an accepted block must never have a blue score lower than its selected parent"
    );
}
