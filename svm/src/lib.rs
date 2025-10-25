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

pub mod account_loader;
pub mod account_overrides;
pub mod message_processor;
pub mod nonce_info;
pub mod program_loader;
pub mod rent_calculator;
pub mod rollback_accounts;
pub mod transaction_account_state_info;
pub mod transaction_balances;
pub mod transaction_commit_result;
pub mod transaction_error_metrics;
pub mod transaction_execution_result;
pub mod transaction_processing_callback;
pub mod transaction_processing_result;
pub mod transaction_processor;

#[cfg_attr(feature = "frozen-abi", macro_use)]
#[cfg(feature = "frozen-abi")]
extern crate solana_frozen_abi_macro;
