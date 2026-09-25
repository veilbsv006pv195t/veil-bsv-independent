# Unsigned recipient correction — local validation

Date: 2026-09-25. This is local regression evidence, not a mined deployment,
external security audit, or proof that an existing on-chain pool was upgraded.

## Correction

Recipient fields are now range-checked as unsigned 160-bit integers, encoded
into 21 little-endian Script-number bytes, and sliced to exactly 20 bytes.
The extra byte accommodates the positive sign. Checking the range before
slicing prevents negative values and overflow aliases. The circuit and
statement layout already use unsigned 20-byte recipients and are unchanged.

The shared encoder is used by both current pool contract variants, the v4
finalizer, browser transaction construction, and lifecycle/test scripts.
The original pool and finalizer remain under `src/v4/legacy/` solely for
reproducing historical deployment evidence; they are not used for new builds.

Groth16 proof generation now reports an indeterminate stage, without a fabricated
percentage. Later preparation milestones resume numeric progress. Preparation
errors stay visible outside the transaction-review dialog. Recipient encoding
is validated before the expensive proof operation.

## Checks completed

- Current v4 contracts compiled successfully.
- All 15 unit tests passed, including exact unsigned encoding at zero,
  `2^159 - 1`, `2^159`, and `2^160 - 1`, the reported recipient regression,
  and rejection of negative/overflow values.
- `npm run test:v4` passed five complete proof/interpreter scenarios: shield,
  and withdrawals to `2^159 - 1`, `2^159`,
  `0xac8f16aa9626b09c7ed8ca6f5fffd82282736418`, and `2^160 - 1`.
- Compiled begin/finalizer scripts rejected negative and overflowing fields;
  finalizers rejected substituted destination outputs and mismatched
  recipient hashes. Existing invalid-proof, tampered-state, successor-code,
  and timeout-recovery checks also passed.
- All tested unlocking scripts stayed below the 500,000-byte target; monitored
  Script numbers stayed below 10,000 bytes.
- `npm run verify:v4:deployed` reproduced the original committed deployment
  hashes exactly from the frozen legacy sources and deployment verification key.
- TypeScript checking and the production browser build passed.
- A separate, unfunded local browser page visibly showed “Generating Groth16
  proof…” with an animated bar and no percentage, then completed a local proof.
  This UI test did not broadcast or attest to a real withdrawal.

## Deployment boundary

The corrected contract code requires a new pool deployment and a new audited
funding plan. Do not combine its artifacts with an existing pool's state or
assume a website refresh upgrades contracts already mined. Keep any original
live-session tab open: its notes are in memory. Recover existing funds through
the original contracts and a supported recipient before retiring that session.
No wallet secrets were read, no public files were published, and no transactions
were broadcast while implementing and validating this correction.
