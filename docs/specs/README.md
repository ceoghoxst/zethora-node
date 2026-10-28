# Early design specs (moved from ceoghoxst/zethora, October 2026)

These specs were written before and during the first code (October 2026)
and moved here from the old ceoghoxst/zethora repository, which is now
archived. They record the original design and reasoning.

**Where these specs disagree with the current docs, the current docs win:**
- Current status and risks: docs/STATUS.md
- Privacy layer as built: docs/ZTH-SPEC-006.md (supersedes ZTH-SPEC-006-privacy.md here)
- Threat model and launch decisions: docs/THREAT-MODEL.md
- Known changes since these were written: privacy is optional
  (transparent by default, private by choice), not private by default;
  mainnet launches without a paid audit and keeps private payments off
  until an independent review (CEO decision 2026-10-28).

Lightpaper v0.2 (PDF) is kept for history; the current lightpaper is
Zethora_Lightpaper_v0.3.md in the repository root.

The reference tools moved to tools/reference/ (emission and fee
calculators) are standalone and not part of the node build.
