# RandomZ: Zethora's tuned RandomX

Zethora mines with RandomX (Monero's CPU proof of work) using its own parameters, so ordinary computers can mine it
but Monero's existing miners and rented hashpower cannot point at it without new software (ZTH-SPEC-000 §4.4,
ZTH-SPEC-005 §5.1). Following RandomX's own guidance (RandomX/doc/configuration.md upstream), only changes that RandomX
documents as safe were made, in `RandomX/src/configuration.h` (and the same values in `RandomX/src/asm/configuration.asm`,
used by Windows builds):

| Parameter | RandomX | RandomZ | Why it is safe |
|---|---|---|---|
| `RANDOMX_ARGON_SALT` | `"RandomX\x03"` | `"RandomZ\x01"` | Every project should pick its own salt |
| `RANDOMX_FREQ_IROR_R` / `IROL_R` | 8 / 2 | 6 / 4 | Rotate right/left are equivalent instructions |
| `RANDOMX_FREQ_FADD_R` / `FSUB_R` | 16 / 16 | 15 / 17 | Add/subtract are equivalent instructions |
| `RANDOMX_FREQ_FADD_M` / `FSUB_M` | 5 / 5 | 6 / 4 | Add/subtract are equivalent instructions |

Memory sizes, program size, iterations and everything else are unchanged, so mining and verification cost exactly what
RandomX costs (2 GiB fast mode for miners, 256 MiB light mode for nodes). Interpreter, JIT, light and fast modes were
checked to give identical hashes for this configuration (Oct 7, 2026).

Upstream: https://github.com/tari-project/randomx-rs (v1.6.0) and https://github.com/tevador/RandomX, both BSD-3-Clause
(see LICENSE and RandomX/LICENSE).
