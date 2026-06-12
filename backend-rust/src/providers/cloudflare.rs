//! Cloudflare provider: under-attack mode, firewall/rate-limit rules. Always
//! read state back to verify; store prior value for exact rollback. Use a scoped
//! API token. See ../skills/cloudflare-api.md.

// TODO(milestone 3): set_security_level, create/delete firewall rule, verify.
