#![cfg_attr(
    not(feature = "agave-unstable-api"),
    deprecated(
        since = "3.1.0",
        note = "This crate has been marked for formal inclusion in the Agave Unstable API. From \
                v4.0.0 onward, the `agave-unstable-api` crate feature must be specified to \
                acknowledge use of an interface that may break without warning."
    )
)]
#![allow(clippy::arithmetic_side_effects)]

pub mod http_sender;
pub mod mock_sender;
pub mod nonblocking;
pub mod rpc_client;
pub mod rpc_sender;
pub mod spinner;
pub use solana_rpc_client_api as api;

pub mod mock_sender_for_cli {
    /// Magic `SIGNATURE` value used by `solana-cli` unit tests.
    /// Please don't use this constant.
    pub const SIGNATURE: &str =
        "43yNSFC6fYTuPgTNFFhF4axw7AfWxB2BPdurme8yrsWEYwm8299xh8n6TAHjGymiSub1XtyxTNyd9GBfY2hxoBw8";
}
