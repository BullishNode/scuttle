# Fallback payouts for expired VTXOs

This fork pays the bitcoin of an expired customer VTXO to an on-chain address
of its owner. Upstream Bark lets the Ark server keep it. `docs/scuttle-protocol.md`
describes the client contract. This page describes the operator side.

## Ownership and payout address

Every customer VTXO has an owner mailbox, fixed when the VTXO is created. The
recipient address carries a proof signed by the VTXO key and by the mailbox
key, in address delivery type `0x03`. The server checks both signatures once
and stores the binding. A VTXO without a valid proof is refused.

The payout goes to the BIP86 address of the mailbox key `M`: `tr(M)` with an
empty script tree. A wallet that derives `M` as the first key of its BIP86
account sees the payout as an ordinary receive.

## Stores and protocol

Use fresh server and wallet stores. The server and the wallet refuse a store
from an earlier fork version. They do not convert it. Clients and the server
must use protocol version 1000.

## Run the payout engine

Run captaind and watchmand against the same database. Fund the watchman fee
wallet through its wallet admin RPC. The watchman pays each payout in an
immutable parent transaction with no fee. Its wallet pays the fee in a separate
child transaction. Without confirmed fee funds, payouts stay pending.

Payouts that share a script and an expiry height pay a total fee of the larger
of 1,000 sats and 1%, rounded up. A VTXO whose share is below the dust limit of
its script can wait up to 144 blocks after expiry for another ready VTXO with
the same payout script, so the two can share one output. After that, the dust
amount is forfeited and the other VTXOs are paid.

## Holds

The server holds a VTXO when it cannot yet decide who is owed it, for example
while a Lightning payment is unresolved. A held VTXO stays spendable,
refreshable and exitable by its owner. The server never sweeps it.

- Run `captaind rpc expiry-holds` to list held VTXOs and the reason for each.
- Monitor the `expiry_holds` gauge.
- A Lightning node that is not online while it has open payments or receives
  logs an error on every node check. Those payments stay open until the node
  is back.

## Lightning

Use the pinned Core Lightning 26.06.6 build with its xpay correction. Configure
`xpay-slow-mode=true` and verify it with `lightning-cli listconfigs xpay-slow-mode`.
Keep matching subdaemons and plugins.

## Wallet behaviour

A VTXO with a committed payout shows as fallback pending and cannot be spent
off-chain. The payout itself arrives at the BIP86 address of the mailbox key,
so the bitcoin wallet of that account finds it, also after a restore from the
seed. Keep wallet backups and the mailbox key.
