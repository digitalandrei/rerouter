---
name: cloudflare-api
description: Using the Cloudflare API as a Rerouter reroute provider — Under-Attack mode, firewall/rate-limit rules, analytics polling, token scoping, and verification. Also covers Cloudflare fronting the app itself.
---

# Skill: Cloudflare API

Cloudflare plays two roles in Rerouter. Keep them separate.

1. **Fronting the app** — `rerouter.cloudcraft.ro` is proxied through Cloudflare;
   the origin (Nginx) restricts inbound 443 to Cloudflare IPs and forwards
   `CF-Connecting-IP` to the controller, which trusts it as the real client IP
   for login throttling, lockout, and audit — safe because only Cloudflare can
   reach Nginx and only Nginx can reach the controller.
   See [../docs/deployment.md](../docs/deployment.md).
2. **A reroute provider** — Rerouter can mitigate Cloudflare-fronted *protected
   assets* via the Cloudflare API.

Use **separate API tokens** for these roles, each least-privilege.

## Auth & tokens

- Use scoped **API tokens** (not the global API key). Store as encrypted provider
  credentials (see [../docs/security.md](../docs/security.md)).
- Token scopes: only the zones in play, only the permissions needed
  (Zone Settings edit, Firewall Services edit, Analytics read).

## Reroute operations (provider type `cloudflare`)

| Template | API action | Verify by |
| --- | --- | --- |
| `cloudflare_under_attack` | set zone `security_level` = `under_attack` | read `security_level` back |
| `cloudflare_restore_security_level` | restore prior `security_level` | read back |
| `cloudflare_firewall_rule` | create a firewall/WAF custom rule (block/challenge) | list rules, confirm present |
| `cloudflare_rate_limit` | create a rate-limit rule | list rules, confirm present |

Always **read back** the resulting state — never treat the API 200 as success.
Store the prior value so rollback restores exactly what was there.

## Analytics (detection + verification)

Poll zone analytics / firewall-events GraphQL for request rate, threat scores, and
challenge/block counts. Use as a detection signal for L7 floods and to confirm an
Under-Attack/firewall reroute is taking effect.

## Practical notes

- Respect API rate limits; back off on 429. Treat 5xx as retryable, 4xx as a
  config/permission error to surface, not retry blindly.
- Record the request and response in `reroute_outputs` (redact the token).
- Capture the rule ID returned on create so rollback can delete exactly that rule.

> When integrating the Anthropic/Claude API anywhere in this project, consult the
> `claude-api` skill for current model IDs and patterns — do not hardcode model
> names from memory.
