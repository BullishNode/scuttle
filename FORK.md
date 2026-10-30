# Scuttle 0.1.0 integration

Scuttle builds on upstream `51781ef693f5da15c9a5aa5720af8c5387652f23`. The
history retains upstream commits and separates fork work by subsystem.
This branch is under construction and is not an installed or qualified release.

| Topic | Purpose and principal touchpoints |
| --- | --- |
| Joint authorization | `lib/src/fallback.rs`, mailbox/address codecs: both coin and mailbox signatures bind the same network, server and recipient intent. Joint address type `0x03` stays. |
| Chain and fees | `bitcoin-ext`, expiry inventory/geometry, watchman: complete signed lineage, canonical conflicts, actual fees and rightful payout accounting. |
| Ownership and payout | `server/src/database/expiry_*`, `server/src/expiry.rs`: retained stage-based entitlement resolution, source fences and payout decisions. |
| Wallet persistence and return | `bark/src/fallback.rs`, persisters and sync: preserve signed bodies and retire paid receipts, including newly imported mailbox deliveries. |
| Issuance and transport | Ark/Mailbox RPCs, `owner_proof`, client address construction: per-output recipient authorization, including outputs for another wallet. |
| Lightning finality | `server/src/ln`, settlement/receive records: retain pending or uncertain obligations and never infer a refund from missing evidence. |
| Native regressions | `testing/tests/scuttle/`: ownership, financial, recovery and wire cases. Existing upstream suites keep their necessary non-mailbox adaptations and share the original helpers. |
| Fork baseline | Fresh Scuttle initial schema plus unchanged upstream PostgreSQL0–77/SQLite0–42 migrations; no fork migration runner. Protocol1000 is required on Ark/Mailbox operations. Scuttle operator methods stay on the existing private admin listener. |
| Application mailbox | The SDK accepts an in-memory mailbox keypair and persists its full public point and network, refusing a missing or changed key on reopen. Application backup/discovery is the caller's responsibility. |
| Remaining switch | Registration remains authoritative in the shadow baseline. The coordinated ownership/Taproot payout switch uses fresh matched stores and refuses older registration-shaped stores; it does not upgrade funded stores. |

The retained registration implementation and old proof read paths are temporary
shadow dependencies, not the final payout or legacy policy. Bitcoin descriptors
have not changed at this baseline. The final recipient contract, strict legacy
refusal, stage resolver, late-completion fences and single payout engine must
land together with their approved tests before the release claim.

## Rebase canary

Run `just fork-canary` from the repository. It uses Git's zero-context diff to
count working-tree modifications against files in the pinned upstream tree,
checks the reviewed per-file budget in `contrib/scuttle-upstream-hunks.json`, and reports
the additions/deletions of each topic commit. The printed HEAD identifies the
commit context, not an immutable result for a potentially dirty working tree.
New fork files are outside this upstream-hunk count; moving tests is not a production-code reduction. Deleted or
binary-changed upstream files also consume a hunk.

A deliberate topic change can require a reviewed budget update. A re-pin also
requires updating the pinned upstream commit and reviewing the resulting delta;
do not increase the budget merely to hide an unexplained conflict. Hunk count
is a conflict/maintenance canary, not evidence that money or signatures are
correct. A production-line comparison must separately exclude tests, docs,
generated code and inline tests; it is a different metric from upstream hunks.

Run the repository's `just checks`, `just unit` and `just int-scuttle` recipes on
exact source/runtime identities. Native tests retain their default180-second
limit, thread1/retry0 qualification recipe and preserved worlds. Source review,
a canary pass and a moved test count do not replace executed financial, recovery
or Signet qualification. Build server and client from matched source and qualify
fresh matched stores before publishing a release.
