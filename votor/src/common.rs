use {
    agave_votor_messages::{consensus_message::Certificate, vote::Vote},
    std::time::Duration,
};

// Core consensus types and constants
pub type Stake = u64;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VoteType {
    Finalize,
    Notarize,
    NotarizeFallback,
    Skip,
    SkipFallback,
}

impl VoteType {
    pub fn get_type(vote: &Vote) -> VoteType {
        match vote {
            Vote::Notarize(_) => VoteType::Notarize,
            Vote::NotarizeFallback(_) => VoteType::NotarizeFallback,
            Vote::Skip(_) => VoteType::Skip,
            Vote::SkipFallback(_) => VoteType::SkipFallback,
            Vote::Finalize(_) => VoteType::Finalize,
        }
    }

    #[allow(dead_code)]
    pub fn is_notarize_type(&self) -> bool {
        matches!(self, Self::Notarize | Self::NotarizeFallback)
    }
}

pub const fn conflicting_types(vote_type: VoteType) -> &'static [VoteType] {
    match vote_type {
        VoteType::Finalize => &[VoteType::NotarizeFallback, VoteType::Skip],
        VoteType::Notarize => &[VoteType::Skip, VoteType::NotarizeFallback],
        VoteType::NotarizeFallback => &[VoteType::Finalize, VoteType::Notarize],
        VoteType::Skip => &[
            VoteType::Finalize,
            VoteType::Notarize,
            VoteType::SkipFallback,
        ],
        VoteType::SkipFallback => &[VoteType::Skip],
    }
}

/// Lookup from `CertificateId` to the `VoteType`s that contribute,
/// as well as the stake fraction required for certificate completion.
///
/// Must be in sync with `vote_to_certificate_ids`
pub const fn certificate_limits_and_vote_types(
    cert_type: Certificate,
) -> (f64, &'static [VoteType]) {
    match cert_type {
        Certificate::Notarize(_, _) => (0.6, &[VoteType::Notarize]),
        Certificate::NotarizeFallback(_, _) => {
            (0.6, &[VoteType::Notarize, VoteType::NotarizeFallback])
        }
        Certificate::FinalizeFast(_, _) => (0.8, &[VoteType::Notarize]),
        Certificate::Finalize(_) => (0.6, &[VoteType::Finalize]),
        Certificate::Skip(_) => (0.6, &[VoteType::Skip, VoteType::SkipFallback]),
    }
}

/// Lookup from `Vote` to the `CertificateId`s the vote accounts for
///
/// Must be in sync with `certificate_limits_and_vote_types` and `VoteType::get_type`
pub fn vote_to_certificate_ids(vote: &Vote) -> Vec<Certificate> {
    match vote {
        Vote::Notarize(vote) => vec![
            Certificate::Notarize(vote.slot(), *vote.block_id()),
            Certificate::NotarizeFallback(vote.slot(), *vote.block_id()),
            Certificate::FinalizeFast(vote.slot(), *vote.block_id()),
        ],
        Vote::NotarizeFallback(vote) => {
            vec![Certificate::NotarizeFallback(vote.slot(), *vote.block_id())]
        }
        Vote::Finalize(vote) => vec![Certificate::Finalize(vote.slot())],
        Vote::Skip(vote) => vec![Certificate::Skip(vote.slot())],
        Vote::SkipFallback(vote) => vec![Certificate::Skip(vote.slot())],
    }
}

pub const MAX_ENTRIES_PER_PUBKEY_FOR_OTHER_TYPES: usize = 1;
pub const MAX_ENTRIES_PER_PUBKEY_FOR_NOTARIZE_LITE: usize = 3;

pub const SAFE_TO_NOTAR_MIN_NOTARIZE_ONLY: f64 = 0.4;
pub const SAFE_TO_NOTAR_MIN_NOTARIZE_FOR_NOTARIZE_OR_SKIP: f64 = 0.2;
pub const SAFE_TO_NOTAR_MIN_NOTARIZE_AND_SKIP: f64 = 0.6;

pub const SAFE_TO_SKIP_THRESHOLD: f64 = 0.4;

/// Time bound assumed on network transmission delays during periods of synchrony.
pub(crate) const DELTA: Duration = Duration::from_millis(250);

/// Time the leader has for producing and sending the block.
pub(crate) const DELTA_BLOCK: Duration = Duration::from_millis(400);

/// Base timeout for when leader's first slice should arrive if they sent it immediately.
pub(crate) const DELTA_TIMEOUT: Duration = DELTA.checked_mul(3).unwrap();

/// Timeout for standstill detection mechanism.
pub(crate) const DELTA_STANDSTILL: Duration = Duration::from_millis(10_000);

/// Returns the Duration for when the `SkipTimer` should be set for for the given slot in the leader window.
#[inline]
pub fn skip_timeout(leader_block_index: usize) -> Duration {
    DELTA_TIMEOUT
        .saturating_add(
            DELTA_BLOCK
                .saturating_mul(leader_block_index as u32)
                .saturating_add(DELTA_TIMEOUT),
        )
        .saturating_add(DELTA)
}

/// Block timeout, when we should publish the final shred for the leader block index
/// within the leader window
#[inline]
pub fn block_timeout(leader_block_index: usize) -> Duration {
    // TODO: based on testing, perhaps adjust this
    DELTA_BLOCK.saturating_mul((leader_block_index as u32).saturating_add(1))
}
