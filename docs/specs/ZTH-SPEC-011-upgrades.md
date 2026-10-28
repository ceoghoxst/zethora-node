# ZTH-SPEC-011: Upgrades and Governance

**Project:** Zethora (ZTHR). Community-built; DeionRaven Labs is lead builder, not owner.
**Status: LOCKED (Oct 2, 2026).** Thresholds and timings OPEN.
**Depends on:** ZTH-SPEC-000, ZTH-SPEC-001 (Section 12), ZTH-SPEC-005.

## 1. Purpose
Let Zethora improve over time with no owner, no admin key, and no way to change the money rules.

## 2. What can never change
2.1 ZTH-SPEC-001 Sections 4-7: supply cap, issuance schedule, genesis (no premine), prohibitions.
2.2 No admin key, pause switch, freeze power, or upgrade key exists for anyone.
2.3 Software that changes these rules is a different coin, not Zethora.

## 3. How changes happen
3.1 **ZIP (Zethora Improvement Proposal):** anyone may write one. Public discussion, review, and testnet trial required.
3.2 **Community input:** X polls and similar gather opinions on priorities and non-security matters. Polls never decide security or consensus rules.
3.3 Node software is open source; every node owner chooses whether to run new versions.

## 4. Activation (LOCKED: hybrid)
4.1 An upgrade ships with a signaling window and a deadline date.
4.2 **Early activation:** if a threshold of recent blocks (proposed 90% over a defined window) signal readiness, it activates early.
4.3 **Deadline activation:** if miners stall, the upgrade activates at the published date anyway for nodes running the new software.
4.4 Result: miners cannot veto forever; users keep final control.
OPEN: threshold, window length, minimum time between release and deadline.

## 5. Keeping mining on home computers (LOCKED: scheduled tweaks)
5.1 RandomZ parameters receive a small scheduled tweak about every 2 years via the normal ZIP + activation process.
5.2 Purpose: make specialized mining chips (ASICs) never worth building.
5.3 Emergency tweak is also possible via the same process if chips appear early.

## 6. Bug fixes and security
6.1 Vulnerabilities are reported privately to maintainers (responsible disclosure), fixed, released, then disclosed publicly.
6.2 Bug bounty (SPEC-006 4.5).
6.3 No emergency pause exists; fixes take effect as node owners install them.

## 7. Threats

| Threat | Mitigation |
|---|---|
| Miners block a needed upgrade | Deadline activation |
| Chain split | Long notice periods, wide communication, testnet first |
| Developer capture (one team pushes bad change) | Open review, multiple implementations encouraged, node owners decide |
| Someone tries to change supply | Section 2; such software is not Zethora |
| ASICs appear | Scheduled tweaks + emergency tweak path |

## 8. Changelog
- Oct 2, 2026: LOCKED: ZIP process, hybrid activation, scheduled ~2-year mining tweaks, frozen money rules, no admin key.
