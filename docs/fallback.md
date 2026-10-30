# Signature-linked fallback payouts

This fork adds payouts for abandoned, expired VTXOs to Bark. It retains
Core Lightning 26.06.6 with the approved xpay terminal-state correction and
upstream wallet exit behavior. It adds no
automatic outage exit scheduler or custom Lightning timeout policy.

Use fresh server and wallet stores. Earlier experimental fork formats are
not converted. The ordinary migration runners create the fallback tables;
registrations and unpaid obligations survive reopening the same store.

The matching clients register an immutable Bitcoin destination with both
mailbox keys. New customer outputs require matching authorization from the
coin key and the linked mailbox key. Recipient addresses use joint signed
delivery type `0x03` and protocol version 7. The recipient signs its address;
the payer copies that proof. The Bitcoin destination can be any supported
address. No Bitcoin private-key proof or common seed is required.
Registration is required before mailbox reads, subscriptions or posts.
Legacy issued rights keep their original proof version. Legacy address and
checkpoint decoding does not authorize new issuance with a coin-only proof.
`bark dev fallback-record` shows the native client's public registration.
SDK applications supply their chosen script through `OpenWalletArgs.fallback_spk`.

Run captaind and watchmand against the same database. Fund the watchman's
existing fee wallet through its wallet admin RPC. The watchman preserves
customer payout amounts in an immutable parent transaction; its wallet funds
a separate fee child. Insufficient confirmed fee funds leave payouts pending.

Payouts sharing a script and expiry height pay a total fee of the larger of
1,000 satoshis and 1% rounded up. A net amount below that script's dust threshold
is forfeited under the payout policy. Unresolved Lightning payments and binding
rounds remain held until the existing contract establishes ownership.

For external Lightning sends, configure the pinned CLN build with `xpay-slow-mode=true`
and verify it with `lightning-cli listconfigs xpay-slow-mode`. Keep matching
subdaemons and plugins. Ordinary upstream timeout failure reporting applies.
The fork does not promise an extended Lightning finality window.

The wallet verifies canonical fallback transactions before treating principal
as paid. Customer allocations have an explicit fallback-pending status.
Only fully validated owned claims contribute to awaiting settlement; an
allocation is not proof of payment. Ordinary spent reports use upstream trust,
including during seed recovery:
a false ordinary-spent report can hide a still-valid claim. Keep wallet backups.
Manual exits and their progression use upstream Bark behavior.
