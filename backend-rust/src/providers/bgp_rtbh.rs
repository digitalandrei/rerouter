//! RTBH blackhole provider: announce /32|/128 with the blackhole community via
//! the controlled BGP speaker. Enforce permitted_prefixes + max length. Verify
//! against the BGP feed; prefer auto-expiry. See ../skills/bgp-reroute-safety.md.

// TODO(milestone 3): announce/withdraw blackhole; verify via telemetry::bgp.
