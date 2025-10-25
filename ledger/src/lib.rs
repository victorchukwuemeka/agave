#![cfg_attr(
    not(feature = "agave-unstable-api"),
    deprecated(
        since = "3.1.0",
        note = "This crate has been marked for formal inclusion in the Agave Unstable API. From \
                v4.0.0 onward, the `agave-unstable-api` crate feature must be specified to \
                acknowledge use of an interface that may break without warning."
    )
)]
#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
#![allow(clippy::arithmetic_side_effects)]
#![recursion_limit = "2048"]

pub mod bank_forks_utils;
pub mod bigtable_delete;
pub mod bigtable_upload;
pub mod bigtable_upload_service;
pub mod block_error;
#[macro_use]
pub mod blockstore;
pub mod ancestor_iterator;
pub mod bit_vec;
pub mod blockstore_cleanup_service;
pub mod blockstore_db;
pub mod blockstore_meta;
pub mod blockstore_metric_report_service;
pub mod blockstore_metrics;
pub mod blockstore_options;
pub mod blockstore_processor;
pub mod entry_notifier_interface;
pub mod entry_notifier_service;
pub mod genesis_utils;
pub mod leader_schedule;
pub mod leader_schedule_cache;
pub mod leader_schedule_utils;
pub mod next_slots_iterator;
pub mod rooted_slot_iterator;

#[cfg(feature = "agave-unstable-api")]
pub mod shred;
#[cfg(not(feature = "agave-unstable-api"))]
pub(crate) mod shred;

mod shredder;
pub mod sigverify_shreds;
pub mod slot_stats;
mod staking_utils;
mod transaction_address_lookup_table_scanner;
pub mod transaction_balances;
pub mod use_snapshot_archives_at_startup;

#[macro_use]
extern crate eager;

#[macro_use]
extern crate solana_metrics;

#[macro_use]
extern crate log;

#[cfg_attr(feature = "frozen-abi", macro_use)]
#[cfg(feature = "frozen-abi")]
extern crate solana_frozen_abi_macro;

#[doc(hidden)]
pub mod macro_reexports {
    pub use agave_snapshots::hardened_unpack::MAX_GENESIS_ARCHIVE_UNPACKED_SIZE;
}

mod wire_format_tests;
