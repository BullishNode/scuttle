-- Initial signature-link schema for fresh fork stores.

CREATE TABLE fallback_record (
	mailbox_pk TEXT PRIMARY KEY,
	spk TEXT NOT NULL,
	mailbox_sig TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX expiry_vtxo_anchor_point_ix ON vtxo (anchor_point, vtxo_id);

CREATE TABLE expiry_entitlement (
	id BIGSERIAL PRIMARY KEY,
	vtxo_id TEXT NOT NULL UNIQUE REFERENCES vtxo(vtxo_id),
	gross_sat BIGINT NOT NULL CHECK (gross_sat > 0),
	irreversible_facts JSONB NOT NULL DEFAULT '{}'::jsonb,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE expiry_cancelled_participation (
	-- Upstream may delete a superseded pending participation. Keep its cancellation tombstone.
	participation_id BIGINT PRIMARY KEY,
	unlock_hash TEXT UNIQUE,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Signed coin links and mailbox registrations are rechecked before payout.
CREATE TABLE expiry_owner_key (
	user_pubkey TEXT PRIMARY KEY,
	mailbox_pk TEXT NOT NULL REFERENCES fallback_record(mailbox_pk),
	blinded_id TEXT NOT NULL CHECK (length(blinded_id) = 66),
	signature TEXT NOT NULL CHECK (length(signature) = 128)
);

-- Chain-derived decisions are invalid until both processes acknowledge their
-- successful sync cycles and the rebuild verifies the current database tips.
CREATE TABLE expiry_chain_view (
	id SMALLINT PRIMARY KEY CHECK (id = 1),
	generation BIGINT NOT NULL DEFAULT 0 CHECK (generation >= 0),
	invalid BOOLEAN NOT NULL DEFAULT TRUE,
	rebuilt_captaind_height BIGINT,
	rebuilt_captaind_hash TEXT,
	rebuilt_watchmand_height BIGINT,
	rebuilt_watchmand_hash TEXT
);
INSERT INTO expiry_chain_view (id) VALUES (1);

CREATE TABLE expiry_sync_ack (
	process TEXT PRIMARY KEY CHECK (process IN ('captaind', 'watchmand')),
	generation BIGINT NOT NULL,
	height BIGINT NOT NULL,
	hash TEXT NOT NULL
);

-- Financial decisions are immutable; active links and chain results are rebuilt.
CREATE TABLE expiry_allocation (
	id BIGSERIAL PRIMARY KEY,
	expiry_height INTEGER NOT NULL CHECK (expiry_height >= 0),
	status TEXT NOT NULL CHECK (status IN ('pending', 'confirmed', 'conflicted')),
	sweep_txid TEXT UNIQUE,
	sweep_tx BYTEA,
	broadcast_at TIMESTAMPTZ,
	confirmed_height BIGINT,
	confirmed_hash TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CHECK ((sweep_txid IS NULL) = (sweep_tx IS NULL)),
	CHECK ((confirmed_height IS NULL) = (confirmed_hash IS NULL))
);

CREATE TABLE expiry_allocation_input (
	allocation_id BIGINT NOT NULL REFERENCES expiry_allocation(id),
	vtxo_id TEXT NOT NULL REFERENCES vtxo(vtxo_id),
	PRIMARY KEY (allocation_id, vtxo_id)
);

CREATE TABLE expiry_allocation_coin (
	allocation_id BIGINT NOT NULL REFERENCES expiry_allocation(id),
	entitlement_id BIGINT NOT NULL REFERENCES expiry_entitlement(id),
	owner_mailbox TEXT REFERENCES fallback_record(mailbox_pk),
	user_pubkey TEXT,
	spk TEXT,
	disposition TEXT NOT NULL CHECK (disposition IN ('customer', 'operator')),
	gross_sat BIGINT NOT NULL CHECK (gross_sat > 0),
	fee_sat BIGINT NOT NULL CHECK (fee_sat >= 0),
	payout_sat BIGINT NOT NULL CHECK (payout_sat >= 0),
	forfeited_sat BIGINT NOT NULL CHECK (forfeited_sat >= 0),
	active BOOLEAN NOT NULL DEFAULT TRUE,
	evidence JSONB NOT NULL,
	PRIMARY KEY (allocation_id, entitlement_id),
	CHECK ((disposition = 'customer' AND owner_mailbox IS NOT NULL AND user_pubkey IS NOT NULL
		AND spk IS NOT NULL AND gross_sat = fee_sat + payout_sat + forfeited_sat)
		OR (disposition = 'operator' AND fee_sat = 0 AND payout_sat = 0 AND forfeited_sat = 0))
);
CREATE UNIQUE INDEX expiry_one_active_allocation_per_coin ON expiry_allocation_coin(entitlement_id) WHERE active;

CREATE TABLE expiry_allocation_payout (
	allocation_id BIGINT NOT NULL REFERENCES expiry_allocation(id),
	output_index INTEGER NOT NULL CHECK (output_index >= 0),
	spk TEXT NOT NULL,
	amount_sat BIGINT NOT NULL CHECK (amount_sat > 0),
	PRIMARY KEY (allocation_id, output_index),
	UNIQUE (allocation_id, spk)
);

-- Splitting is a chain action, not another payout decision or customer fee.
CREATE TABLE expiry_split_request (
	vtxo_id TEXT PRIMARY KEY REFERENCES vtxo(vtxo_id),
	progress_txid TEXT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE expiry_terminal_claim (
	entitlement_id BIGINT PRIMARY KEY REFERENCES expiry_entitlement(id),
	txid TEXT NOT NULL,
	height BIGINT NOT NULL CHECK (height >= 0),
	hash TEXT NOT NULL
);

-- A collected forwarding receive names its final payee independently of the
-- provider's grant key. Outcome remains the upstream subscription's status.
CREATE TABLE expiry_lightning_receive_claim (
	source_vtxo_id TEXT PRIMARY KEY REFERENCES vtxo(vtxo_id),
	subscription_id BIGINT NOT NULL REFERENCES lightning_htlc_subscription(id),
	payment_hash TEXT NOT NULL,
	output_vtxo_id TEXT NOT NULL UNIQUE,
	output_vtxo BYTEA NOT NULL
);
