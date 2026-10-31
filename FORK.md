# Scuttle 0.1.0 integration

Scuttle builds on upstream `51781ef693f5da15c9a5aa5720af8c5387652f23`. The
history retains upstream commits and separates fork work by subsystem.
This branch is not released yet. Implementation and qualification are incomplete.

| Topic | Purpose and principal touchpoints |
| --- | --- |
| Joint authorization | `lib/src/fallback.rs`, mailbox/address codecs: both coin and mailbox signatures bind the same network, server and recipient intent. Joint address type `0x03` stays. |
| Chain and fees | `bitcoin-ext`, expiry inventory/geometry, watchman: complete signed lineage, canonical conflicts, actual fees and payout accounting. |
| Ownership and payout | `server/src/database/expiry_*`, `server/src/expiry.rs`: retained stage-based entitlement resolution, source fences and payout decisions. |
| Wallet persistence and return | `bark/src/fallback.rs`, persisters and sync: preserve signed bodies and retire paid receipts, including newly imported mailbox deliveries. |
| Issuance and transport | Ark/Mailbox RPCs, `owner_proof`, client address construction: per-output recipient authorization, including outputs for another wallet. |
| Lightning finality | `server/src/ln`, settlement/receive records: retain pending or uncertain obligations and never infer a refund from missing evidence. |
| Native regressions | `testing/tests/scuttle/`: ownership, financial, recovery and wire cases. Existing upstream suites keep their necessary non-mailbox adaptations and share the original helpers. |
| Fork baseline | Fresh Scuttle initial schema plus unchanged upstream PostgreSQL 0–77 and SQLite 0–42 migrations; no fork migration runner. Protocol 1000 is required on Ark/Mailbox operations. Scuttle operator methods stay on the existing private admin listener. |
| Application mailbox | The SDK accepts an in-memory mailbox keypair and persists its full public point and network, refusing a missing or changed key on reopen. Application backup/discovery is the caller's responsibility. |
| Ownership switch | Joint admission and immutable birth ownership supply stage-selected BIP86 payouts. Explicit authenticated receipts replace the client ancestry ledger. Fresh matched stores refuse older registration-shaped stores instead of upgrading them. |

Registration and legacy proof dispatch are removed. Both joint signatures and
address type `0x03` remain mandatory; the server derives the stage-entitled
mailbox's Taproot destination. The default test client's mailbox follows its
existing BIP86 external index-zero descriptor. External mailbox applications
remain responsible for their corresponding Bitcoin account and backup.

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

Run `just checks`, `just unit` and `just int-scuttle` on exact source and runtime
identities. A canary or source review does not replace the required financial,
failure, recovery and Signet qualification. Preserve failures and funded stores.
Build the server and client from the same source and qualify fresh matched stores
before a release.
