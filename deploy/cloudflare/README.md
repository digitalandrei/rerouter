# Cloudflare (fronting the app)

The Rerouter web app is served behind Cloudflare at `rerouter.cloudcraft.ro`.
This directory documents that fronting setup. Cloudflare is *also* usable as a
reroute provider for protected assets — that is a **separate** concern with a
**separate** API token (see [../../skills/cloudflare-api.md](../../skills/cloudflare-api.md)).

## DNS

- `rerouter` → origin IP, **proxied** (orange cloud).

## TLS

- Origin: install a Cloudflare **Origin Certificate** on Nginx
  (`/etc/ssl/rerouter/origin.pem` + `.key`).
- SSL/TLS mode: **Full (strict)**.

## Lock the origin

The origin must not be reachable directly (attackers bypass Cloudflare otherwise):

- Firewall: allow inbound 443 only from current Cloudflare IP ranges
  (https://www.cloudflare.com/ips). Mirror the list into the Nginx
  `set_real_ip_from` include.
- Consider `cloudflared` tunnel instead of opening 443 at all.

## Real client IP

Cloudflare sends the true client IP in `CF-Connecting-IP`. Nginx restores it
(`real_ip_header CF-Connecting-IP`) and forwards it to the Rust controller,
which trusts it because only Cloudflare can reach Nginx and only Nginx can
reach the controller (loopback bind) — so login throttling, account lockout,
and audit logs use the real source. Trust the header only from Cloudflare
ranges.

## Caching / WAF

- Bypass cache for the authenticated app; cache only static assets.
- Enable Cloudflare WAF managed rules for the app hostname.

## Tokens

Keep the token (if any) used to manage *this* zone separate from the
provider tokens used to mitigate protected assets. Least-privilege each.
