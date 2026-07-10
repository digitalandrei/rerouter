# Cloudflare (fronting the app)

The Rerouter web app is served behind Cloudflare at `rerouter.cloudcraft.ro`.
This directory documents that fronting setup. Cloudflare is not a reroute
provider in this codebase; device CLI over SSH is the only actuator.

## DNS

- `rerouter` → origin IP, **proxied** (orange cloud).

## TLS

- Origin: install a Cloudflare **Origin Certificate** on Nginx
  (`/etc/ssl/rerouter/origin.pem` + `.key`).
- SSL/TLS mode: **Full (strict)**.

## Lock the origin

The origin must not be reachable directly (attackers bypass Cloudflare otherwise):

- Run `./update-origin-ranges.sh` as root to fetch Cloudflare's current IPv4/IPv6
  lists and atomically write
  `/etc/nginx/snippets/rerouter-cloudflare-origin-ranges.conf`. Then run
  `nginx -t && systemctl reload nginx`.
- Firewall: allow inbound 443 only from the same current Cloudflare IP ranges.
- Keep the Nginx exact-host guard for `rerouter.cloudcraft.ro`; the source ranges
  belong to all Cloudflare customers, not only this zone.
- Consider `cloudflared` tunnel instead of opening 443 at all.

## Real client IP

Cloudflare sends the true client IP in `CF-Connecting-IP`. Nginx deliberately
keeps `$remote_addr` as the connecting Cloudflare proxy so its `allow`/`deny`
origin ACL remains effective, then forwards Cloudflare's overwritten header to
the loopback Rust controller for login throttling, account lockout, and audit.
Do not enable `real_ip_header` in this server block: it would make `allow` test
the end-client address and reject legitimate proxied requests.

## Caching / WAF

- Bypass cache for the authenticated app; cache only static assets.
- Enable Cloudflare WAF managed rules for the app hostname.

No Cloudflare API token is required by Rerouter itself.
