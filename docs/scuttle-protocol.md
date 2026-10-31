# Scuttle ownership and fallback

Scuttle identifies a customer coin by its spending public key and an independently
authorized mailbox. The spending key holder and mailbox key holder both sign the
same server- and network-bound owner intent. A sender copies that proof from the
recipient's address when creating an output for them; it supplies its own proof
for change. A request's submitting wallet does not determine the output's owner.

The registration programme is removed. Fresh matched server and wallet stores
use one atomic Scuttle initializer alongside the unchanged upstream migration
history. Registration-shaped or incompatible stores are refused before writes;
keep their original software and data. Source implementation is distinct from
executed native qualification and release approval.

## Wire contract

The Scuttle protocol epoch is `1000`. Clients negotiate it through `Handshake`;
all other Ark and Mailbox methods except the bootstrap information request require
the negotiated version. This includes recovery, status, streams and retry paths.
The operator service uses the configured private administrative listener, never
the public Ark or Mailbox routes. Its network trust boundary is unchanged.

New functional fork fields use tags `1000` and above. Upstream invoice
`expiry_secs` retains tag `6`. The four retired owner-proof slots (board `7`,
VTXO request `3`, arkoor destination `3`, receive-claim preparation `6`) are
decode-only optional-byte tombstones. Any presence, including an empty value or
a mixture with a valid current proof, is rejected before effects. Those numbers
are permanently unavailable for functional reuse; unrelated reserved tags stay
reserved. Address type `0x03` carries the joint
owner proof. The proof commits to its version, genesis hash, server mailbox key,
full compressed spending key and blinded mailbox point. The coin half uses
`Ark/ExpiryOwnerLink/Coin/v2`; the mailbox half uses
`Ark/ExpiryOwnerLink/Mailbox/v2`. Their signatures are not interchangeable.

Coin and mailbox points retain their full compressed parity. X-only conversion
is used for BIP340 verification and BIP341 Taproot construction, not to compare
persisted mailbox identities. No signature proves a common human, common seed,
or ownership of an unrelated Bitcoin spending key.

## Admission, birth and delivery

Admission verifies both signatures and stores an immutable `owner_key` binding.
The same spending key, mailbox and signed fields are an idempotent replay even
if a valid signature differs; the first verified proof is retained. A different
binding for that key is refused. Recovery hints neither establish nor change it.

Customer births are `Spendable`, `Unregistered`, `Unclaimed` and
`HtlcRecvUnclaimed`. The issuing transaction writes the verified key binding,
then the VTXO, then its `coin_owner` row. The deferred constraint checks the
paired row at commit. Operator pool, forfeits, connectors and the server's exact
unspendable round padding policy do not become customer claims. Knowing the
padding public point does not bypass the issuing signature verifier.

Every spendable-coin delivery checks the entire batch against its destination
mailbox before allocating a checkpoint, in the same insertion transaction. A
mixed or incomplete ownership batch is refused atomically. A valid repeated post remains idempotent. Recovery-ID posts are
hints only: they may name an existing foreign coin without assigning ownership
to the recovery mailbox. An unknown ID fails the existing foreign-key constraint;
a mixed known/unknown post rolls back atomically.

## Economic payee and payout script

Birth ownership does not replace the economic stage resolver. Ordinary coins
use their birth mailbox. An unregistered transfer may still owe the input owner;
a collected forwarded receive owes its committed claim destination, even if its
final output was not inserted. Round participation and per-source Lightning
finality retain their existing evidence rules. A provider's mailbox is not copied
onto a recipient's output. An unresolved obligation is held; time or a failed
RPC does not turn it into a refund or operator income.

After selecting the entitled spending key, the derived payout path resolves its
mailbox `M` and constructs BIP86 `tr(M)` with an empty script tree. BIP341 lifts
the x-coordinate to even Y before applying `TapTweak`. A default mnemonic wallet
uses its standard BIP86 account, external index zero; an application may supply
its mailbox keypair explicitly and is responsible for that key's backup and
discovery. The default test wallet derives its mailbox at `m/86'/coin'/0'/0/0`,
matching its native BIP86 external index-zero descriptor. The Ark spending-key
branch remains separate. Restoring an external mailbox requires its original
key, network, account, passphrase and discovery policy; the protocol does not
prove those backup choices.

Payout aggregation is per mailbox, expiry and allocation group; size limits can
create several groups. Existing cumulative fee and dust rules apply. A signature
over the mailbox authorization challenge cannot authorize a Bitcoin input:
mailbox authorization hashes its fixed prefix and expiry timestamp, while a
key-path Bitcoin spend uses the transaction-specific BIP341 `TapSighash` and the
Taproot-tweaked key.

## Client and restore contract

Supply the same external mailbox keypair at each open. The wallet persists its
public identity, full parity and network, and refuses a different identity before
network synchronization. Generate a joint link whenever deriving a spending key;
transport the recipient's link for recipient outputs and the wallet's own link
for board, change, self-round and HTLC-send outputs.

Recovery and status responses carry `owner_mailbox`. Batch and mailbox responses
bind each mailbox to a VTXO ID using `core.VtxoOwner`; request duplicates and
response ordering do not change that association. A missing entry means ownership
is unresolved, not that the requester owns the coin. Foreign ownership does not
hide the signed body from its spending-key holder. Clients count a coin only when
its established mailbox matches their own, including after seed recovery.

The existing authenticated status and mailbox surfaces carry explicit per-entitlement
`core.FallbackClaim` receipts: entitlement ID, allocation ID, entitled mailbox, actual gross/fee/payout/
forfeited amounts, parent/output locator and the server's canonical confirmation
observation. The authenticated mailbox pages these independently of its message
checkpoint, including on an empty-store restore. Explicit source and claim-output
aliases come from the server's existing input-owner and collected-receive mappings;
they do not change a coin's birth owner. Several allocated leaves may name one
original input, while an unmaterialized recipient claim need not have a native
VTXO row. Each entitlement counts once, and its aliases fence local operations
without creating another coin or retiring a foreign mailbox's coin. No receipt
or balance is inferred from a wallet operation graph.
`FALLBACK_FORFEITED` is a terminal no-output policy result, not `Spent` or a
Bitcoin payment. A zero-output receipt reports whether its attributable amount
was consumed by fees or forfeited below dust.

An undecided held coin remains spendable, refreshable and exitable. A committed
`FALLBACK_PENDING` claim is already fenced off-chain: wait for its canonical
payout or a terminal forfeiture. A paid claim names its canonical output. The
wallet independently requires six canonical confirmations and the actual
mailbox-derived output script and value before retirement; the native Bitcoin
account counts an aggregated output once. `Wallet::fallback_receipts` retains
per-entitlement attribution, and history is keyed by entitlement rather than by a retry.
The wallet does not infer a Lightning failure, refund or preimage from a payout. Revisit retired receipts on reopen and status
reads; an orphaned receipt returns to pending, without a duplicate history credit.

Release canceled-round inputs only after the authenticated cancellation for the
exact participation, and only if no forfeit could have been exposed. Persist the
cancellation before unlocking. An unknown round is not cancellation. A restore
re-derives or imports the backed-up mailbox key and applies the same ownership and
canonical-receipt rules.

The initial release uses fresh matched Scuttle stores. It retains upstream
migration payloads and runners unchanged; it does not upgrade funded registration-
era Scuttle stores. Unrecognized, partial or incompatible stores are refused
before writes instead of being silently repaired.
