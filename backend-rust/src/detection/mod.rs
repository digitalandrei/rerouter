//! Detection engine — stateful evaluation of DDoS detection rules.
//! See ../docs/detection-engine.md.
//!
//! A rule firing is a *signal*. Whether it triggers a reroute, an email alert, or
//! both is configured per rule and gated again by the reroute safety model.

pub mod condition;
pub mod cooldown;

/// Lifecycle of a detection rule's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleState {
    Clear,
    Matching, // condition true but duration/consecutive threshold not yet met
    Firing,   // sustained match -> emit event, alert and/or hand off to reroute
}

/// Evaluate whether a sustained match has been reached.
/// Stale or invalid samples must be filtered out *before* calling this.
pub fn is_sustained(consecutive_matches: u32, required: u32) -> bool {
    consecutive_matches >= required
}

// TODO(milestone 2): load rules, evaluate against AssetMetrics, advance
// RuleState with hysteresis, write rule_events, enqueue alerts, hand off to the
// reroute engine (which re-checks every safety gate).
//
// OBSERVE MODE: when system_settings.operating_mode == "observe" (the default),
// a firing rule still records its event and alert, but the alert payload must
// include the rendered would-run plan from the attached reroute template
// ("would have executed: blackhole_prefix prefix=… via provider=…") instead of
// any execution. See ../reroute/executor.rs GATE 0.
