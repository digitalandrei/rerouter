//! Reroute action templates — the ONLY way a reroute can happen. No free-text
//! execution. Each template: provider type, mode, parameter schema, safety level,
//! verification method, rollback template, optional auto-expiry.
//! See ../docs/reroute-engine.md for the catalog (cloudflare_under_attack,
//! blackhole_prefix, flowspec_drop, divert_to_scrubber, ...).

// TODO(milestone 3): load templates, validate params against schema, render plan.
