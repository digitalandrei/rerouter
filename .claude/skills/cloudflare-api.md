---
name: cloudflare-api
description: Cloudflare's role in Rerouter — it fronts the controller's own UI/API (CDN + WAF + CF-Connecting-IP), and is NOT a reroute/mitigation provider. Covers token scoping for the fronting role and why no Cloudflare reroute path exists.
---

# Skill: Cloudflare (app fronting only)

> **Cloudflare is NOT a reroute provider in Rerouter.** It is **only** the
> app-fronting / CDN + WAF layer in front of the controller's **own** web UI and
> API. The controller never calls the Cloudflare API to mitigate customer traffic;
> mitigation is Cisco IOS over SSH (see
> [bgp-reroute-safety](bgp-reroute-safety.md)). The old "Cloudflare reroute
> provider" (Under-Attack / firewall / rate-limit templates, `provider_type =
> cloudflare`) was **de-scoped**: the enum value lingers with no executor, and
> there are no `cloudflare_*` reroute templates.

## The one role: fronting the app

`rerouter.cloudcraft.ro` is proxied through Cloudflare; the origin (Nginx)
restricts inbound 443 to **Cloudflare IP ranges** and forwards `CF-Connecting-IP`
to the controller, which trusts it as the real client IP for login throttling,
account lockout, and audit — safe because **only** Cloudflare can reach Nginx and
**only** Nginx can reach the loopback-bound controller. See
[deployment.md](../../docs/deployment.md) and
[security.md](../../docs/security.md).

That is the whole integration. There is no controller → Cloudflare API egress
path in v1: no zone-settings edits, no firewall/WAF rule creation, no analytics
polling. (`docs/telemetry-model.md` lists Cloudflare zone analytics only as a
*future, not-implemented* detection signal.)

## Tokens & trust (fronting role)

- This deployment is configured in the Cloudflare dashboard / DNS, not via an API
  token the controller holds. If a token is ever introduced for managing the
  fronting zone, use a **scoped API token** (not the global key), least-privilege,
  and store it as an encrypted secret — never re-expose it in the UI (see
  [security.md](../../docs/security.md)).
- Trust `CF-Connecting-IP` **only** over the Cloudflare → Nginx → loopback path.
  Never trust a client-supplied `CF-Connecting-IP` reaching the controller by any
  other route.
- Keep Nginx's `$remote_addr` as the Cloudflare connection for its origin
  `allow`/`deny` ACL. Forward Cloudflare's overwritten client header only after
  that ACL; enabling `real_ip_header` in the same server would make the ACL test
  the end-client address and reject legitimate traffic.

## If asked to "reroute through Cloudflare"

Surface the conflict: it contradicts the de-scoped model. v1 mitigates on the
routers it manages (Null0 null-route, tagged-Null0 RTBH the router redistributes
upstream, BGP neighbor shut/no-shut) over SSH via templates — not via Cloudflare.

> When integrating the Anthropic/Claude API anywhere in this project, consult the
> `claude-api` skill for current model IDs and patterns — do not hardcode model
> names from memory.
