//! Cooldown bookkeeping shared by detection (per-rule) and reroute (per-asset,
//! per-prefix/provider, global rate limit). See ../docs/reroute-engine.md.

// TODO(milestone 3): is_in_cooldown(scope) + record_cooldown(scope, until).
