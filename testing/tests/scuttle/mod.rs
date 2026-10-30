//! Scuttle-specific financial, ownership, recovery and wire regressions.
//! Existing upstream test adaptations remain in their original binaries.

#[path = "server/mod.rs"]
mod server_tests;
#[path = "bark_sdk/mod.rs"]
mod sdk;
#[path = "barkd/mod.rs"]
mod daemon;
#[path = "../barkd/helpers.rs"]
mod helpers;
