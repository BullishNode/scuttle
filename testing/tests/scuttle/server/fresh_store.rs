use ark_testing::TestContext;
use server::database::Db;

/// Only upstream has a migration history; Scuttle initializes once on a fresh DB.
#[tokio::test]
async fn fresh_scuttle_schema_reopens_without_history_changes() {
	let mut ctx = TestContext::new_minimal("postgresd/fresh_scuttle_schema_reopen").await;
	ctx.init_central_postgres().await;
	let cfg = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&cfg, bitcoin::Network::Regtest).await.unwrap();
	let client = ctx.postgres_manager().database_client(Some(&cfg.name)).await;
	let version: i32 = client.query_one("SELECT MAX(version) FROM public.refinery_schema_history", &[])
		.await.unwrap().get(0);
	assert_eq!(version, 77);
	assert!(client.query_one("SELECT to_regclass('scuttle.refinery_schema_history') IS NULL", &[])
		.await.unwrap().get::<_, bool>(0));
	let missing: i64 = client.query_one(
		"SELECT COUNT(*) FROM unnest(ARRAY['fallback_record', 'expiry_owner_key', \
		 'expiry_allocation', 'expiry_allocation_coin', 'expiry_lightning_receive_claim', \
		 'owner_key', 'coin_owner', 'expiry_hold', 'htlc_settlement_source']) AS names(name) \
		 WHERE to_regclass('scuttle.' || name) IS NULL", &[],
	).await.unwrap().get(0);
	assert_eq!(missing, 0);
	assert!(client.query_one("SELECT to_regclass('public.fallback_record') IS NULL", &[])
		.await.unwrap().get::<_, bool>(0));
	let history = "SELECT version || ':' || name || ':' || applied_on || ':' || checksum \
		FROM public.refinery_schema_history ORDER BY version";
	let before = client.query(history, &[]).await.unwrap().into_iter()
		.map(|row| row.get::<_, String>(0)).collect::<Vec<_>>();
	Db::connect(&cfg, bitcoin::Network::Regtest).await.unwrap();
	let after = client.query(history, &[]).await.unwrap().into_iter()
		.map(|row| row.get::<_, String>(0)).collect::<Vec<_>>();
	assert_eq!(before, after);
}

#[tokio::test]
async fn old_fork_database_is_refused_before_initialization_writes() {
	let mut ctx = TestContext::new_minimal("postgresd/old_fork_database_refused").await;
	ctx.init_central_postgres().await;
	let cfg = ctx.new_postgres(&ctx.test_name).await;
	let client = ctx.postgres_manager().database_client(Some(&cfg.name)).await;
	client.batch_execute("CREATE TABLE public.refinery_schema_history (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_on TEXT NOT NULL, checksum TEXT NOT NULL
	);
	INSERT INTO public.refinery_schema_history VALUES (73, 'signature_link_fallback', 'original', 'original');
	CREATE TABLE public.fallback_record (mailbox_pk TEXT PRIMARY KEY, spk TEXT NOT NULL, mailbox_sig TEXT NOT NULL);
	INSERT INTO public.fallback_record VALUES ('original-mailbox', 'original-script', 'original-signature');").await.unwrap();
	let tables = client.query("SELECT schemaname || '.' || tablename FROM pg_catalog.pg_tables \
		WHERE schemaname NOT IN ('pg_catalog', 'information_schema') ORDER BY 1", &[]).await.unwrap()
		.into_iter().map(|row| row.get::<_, String>(0)).collect::<Vec<_>>();
	let error = match Db::connect(&cfg, bitcoin::Network::Regtest).await {
		Ok(_) => panic!("old fork store must be refused"),
		Err(error) => error,
	};
	assert!(format!("{error:#}").contains("not a fresh Scuttle store"));
	let after = client.query("SELECT schemaname || '.' || tablename FROM pg_catalog.pg_tables \
		WHERE schemaname NOT IN ('pg_catalog', 'information_schema') ORDER BY 1", &[]).await.unwrap()
		.into_iter().map(|row| row.get::<_, String>(0)).collect::<Vec<_>>();
	assert_eq!(tables, after);
	let original = client.query_one("SELECT version, name, applied_on, checksum FROM public.refinery_schema_history", &[])
		.await.unwrap();
	assert_eq!(original.get::<_, i32>(0), 73);
	assert_eq!(original.get::<_, &str>(1), "signature_link_fallback");
	assert_eq!(original.get::<_, &str>(2), "original");
	assert_eq!(original.get::<_, &str>(3), "original");
	let original = client.query_one("SELECT mailbox_pk, spk, mailbox_sig FROM public.fallback_record", &[]).await.unwrap();
	assert_eq!(original.get::<_, &str>(0), "original-mailbox");
	assert_eq!(original.get::<_, &str>(1), "original-script");
	assert_eq!(original.get::<_, &str>(2), "original-signature");
}
