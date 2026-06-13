//! Reroute engine — controlled, audited mitigations that move traffic.
//! THE most dangerous part of the system. See ../docs/reroute-engine.md and
//! ../agents/reroute-safety-agent.md.

pub mod executor;
pub mod locks;
pub mod state_machine;
pub mod templates;
pub mod rollback;

/// Safety level of a reroute template; scales the required confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyLevel {
    Low,    // e.g. Cloudflare under-attack (easily reversible)
    Medium, // e.g. rate-limit rule
    High,   // blackhole / withdraw / scrub-divert (typed confirmation + re-auth)
}

/// How a reroute was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerType { Automatic, Manual, Rollback }

/// Result of the pre-execution safety gate. Anything other than `Allowed`
/// aborts and is logged with the reason.
#[derive(Debug, Clone)]
pub enum GateDecision {
    Allowed,
    Blocked(&'static str),
}
