# Fallback payouts for expired VTXOs

Scuttle pays eligible expired customer VTXOs on-chain after it can establish
who is owed them. Unresolved obligations stay held. `docs/scuttle-protocol.md`
describes the client contract. This page describes the operator side.

## Ownership and payout address

Every customer VTXO has an owner mailbox, fixed when the VTXO is created. The
recipient address carries a proof signed by the VTXO key and by the mailbox
key, in address delivery type `0x03`. The server checks both signatures once
and stores the binding. A VTXO without a valid proof is refused.

The economic stage selects the entitled spending key before the server resolves
its mailbox. An unfinished transfer can still owe its input owner; a collected
forwarded receive owes its committed claim destination. Birth ownership alone
does not select the payee in these cases.

The payout goes to the BIP86 address of that mailbox key `M`: `tr(M)` with an
empty script tree. A wallet that derives `M` at external index zero of its BIP86
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

Payouts in one allocation group that share a script and an expiry height pay a
total fee of the larger of 1,000 sats and 1%, rounded up. Size limits can create
several groups. An otherwise ready VTXO whose share is below its script's dust
limit can wait up to 144 blocks after expiry for another ready VTXO with the same
script and expiry. The dust policy then applies. This deadline does not release
an unresolved payment, ownership or integrity hold.

## Holds

The server holds a VTXO when it cannot yet decide who is owed it, for example
while a Lightning payment is unresolved. An undecided hold does not itself block
ordinary spending, refresh or emergency exit. Existing Lightning and round
restrictions still apply. A committed fallback claim is already fenced
off-chain and must wait for its canonical payout or terminal forfeiture.

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

A VTXO with a committed payout shows as fallback pending. The wallet requires
six canonical confirmations and checks the actual payout script and value
before it retires the claim. A reorg returns the claim to pending.

The default wallet's seed phrase recovers its BIP86 mailbox account. An
application that supplies an external mailbox must back up its original key,
network, account, passphrase and discovery policy. The protocol does not prove
that backup. Ordinary spent reports retain upstream server trust; a false
ordinary-spent report can hide a still-valid claim. Keep wallet backups.
