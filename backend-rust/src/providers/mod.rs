//! Reroute provider adapters — the channels we reroute *through*. Each adapter
//! can execute its supported templates AND verify the resulting state.
//! See ../docs/asset-enrollment.md and ../skills/.

pub mod cloudflare;
pub mod bgp_rtbh;
pub mod flowspec;
pub mod scrubber;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderType { Cloudflare, BgpRtbh, Flowspec, Scrubber }

/// Outcome of a provider-side verification read. Ambiguity => Uncertain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyResult { Pass, Fail, Uncertain }

// A provider adapter should expose: execute(plan) and verify(expectation).
// Adapters must never panic; surface structured errors so the executor can
// decide failed vs uncertain.
