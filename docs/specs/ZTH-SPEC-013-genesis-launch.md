# ZTH-SPEC-013: Genesis and Launch

**Project:** Zethora (ZTHR).
**Status: LOCKED (Oct 2, 2026).**
**Depends on:** ZTH-SPEC-001 (Section 6), ZTH-SPEC-005, ZTH-SPEC-012.

## 1. Purpose
Launch Zethora so that everyone in the world starts at the same moment, with proof that no one started early.

## 2. Locked decisions

| Decision | Value |
|---|---|
| Genesis supply | 0 ZTHR |
| Pre-launch mining | None by anyone, including the founder |
| Software | Published before launch so anyone can inspect and prepare |
| Announcement | Launch date announced 1 month in advance (after all SPEC-012 gates pass) |
| Slow start | None. Full block rewards from block 1 |
| Early fairness | Fast difficulty adjustment from block 1; starting difficulty set from testnet measurements |
| Date proof | Genesis block includes the hash of the most recent Bitcoin block at launch time |
| Genesis message | **"Wake Up From The Dream World"** |

## 3. Launch sequence
1. All SPEC-012 launch gates pass.
2. Final software published (open source) with genesis parameters except the Bitcoin hash.
3. Launch date announced publicly, 1 month ahead.
4. At launch time: the latest Bitcoin block hash is inserted into the genesis block with the genesis message; genesis is published.
5. Anyone in the world begins mining at the same moment.

## 4. Verification
Anyone can confirm: genesis contains 0 coins; the embedded Bitcoin block hash did not exist before launch time; the message matches this spec.

## 5. Changelog
- Oct 2, 2026: LOCKED: 1-month announcement, no slow start, fast difficulty adjustment, Bitcoin-hash date proof, genesis message "Wake Up From The Dream World".
