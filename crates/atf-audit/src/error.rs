use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
#[error("audit hash chain broken at event index {index}: recorded prev_event_hash does not match the actual hash of the preceding event")]
pub struct ChainVerificationError {
    pub index: usize,
}
