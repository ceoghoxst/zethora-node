# Persistence Rules (STANDING)

Everything we decide, claim, or build must survive the chat session.
The chat is ephemeral. Files on disk are permanent.

## Rules

1. **Every decision goes into a doc.** Strategy, claim, spec, or scope change
   gets a file. Chat alone is not a decision.
2. **Every session ends with a CEO briefing** at
   `docs/CEO-BRIEFING-YYYY-MM-DD.md`. Plain English. What was done, why, how
   verified.
3. **Every spec claim cites file:line.** No claim without evidence.
4. **The audit trail lives in CLAUDE.md.** Consensus changes, test results,
   known gaps, all appended. Never rewritten, always appended.
5. **Do-not-claim list lives in CLAUDE.md.** Any public claim that we cannot
   back with code is explicitly forbidden there.

## File map (what lives where)

| File | Purpose | Who reads it |
|---|---|---|
| `CLAUDE.md` | Internal audit trail for CTO and Lead Engineer | Claude, me, you |
| `docs/CEO-BRIEFING-YYYY-MM-DD.md` | Plain-English session summary | CEO |
| `docs/ZTH-SPEC-006.md` | Privacy layer spec | Reviewers, auditors |
| `docs/TESTNET-ROADMAP.md` | Testnet milestones | Internal |
| `README.md` | Public front door | Everyone |
| `docs/ZTH-IMPL-020-*.md` | DoS protection spec | Auditors |
| `docs/PERSISTENCE-RULES.md` | This file | Internal |
| `docs/LIGHTPAPER-INTRO.draft.md` | Lightpaper intro draft | Draft only |
| `README.draft.md` | README rewrite draft | Draft only |

## When a new decision happens

1. Write it into the appropriate existing file (or create a new one).
2. Commit it with a clear message.
3. If it changes a public claim, update the do-not-claim list in CLAUDE.md.

## When a session ends

1. Write `docs/CEO-BRIEFING-YYYY-MM-DD.md` if not already current.
2. `git add` and `git commit -m "Docs: CEO briefing YYYY-MM-DD"`.
3. `git push origin zethora`.

No exceptions. Not "I forgot." The rule is the rule.