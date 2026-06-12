//! Rollback + auto-expiry. Every disruptive template defines a rollback
//! (withdraw_blackhole_prefix, flowspec_remove_rule, stop_diversion,
//! cloudflare_restore_security_level). Rollbacks are themselves audited and
//! verified. Blackholes prefer auto-expiry so a forgotten mitigation self-clears.

// TODO(milestone 3): schedule expiry; run + verify rollback as an audited action.
