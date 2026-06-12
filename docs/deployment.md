# Deployment

Dev/prod target: Ubuntu 24.04. The site is fronted by **Cloudflare** at
`rerouter.cloudcraft.ro`; **Nginx** is the origin web server, serving the static
SPA build and reverse-proxying the API. The **Rust controller** runs as a
systemd service and binds its API to localhost only.

## Topology

```text
Internet
  -> Cloudflare (TLS, WAF, proxy)  [rerouter.cloudcraft.ro]
       -> Nginx :443 (origin)
            -> static SPA          (frontend/dist, served directly)
            -> location /api/      -> http://127.0.0.1:9277 (Rust controller)
       (the controller is reachable ONLY through the /api/ proxy)
```

## Cloudflare

- DNS record `rerouter` is **proxied** (orange cloud) to the origin IP.
- Origin TLS: use a Cloudflare **Origin Certificate** on Nginx and set SSL mode to
  **Full (strict)**. Do not serve the origin with a public Let's Encrypt cert that
  Cloudflare can't validate as strict unless you prefer that path.
- Lock the origin down: allow inbound 443 only from Cloudflare IP ranges
  (`cloudflared` or firewall allowlist), so the origin cannot be hit directly.
- Because Cloudflare proxies, the **real client IP** arrives in
  `CF-Connecting-IP`. Configure Nginx `real_ip` from Cloudflare ranges and
  forward the header to the controller, which trusts it for login throttling,
  account lockout, and audit logs — safe because only Cloudflare can reach
  Nginx and only Nginx can reach the controller.
- Caching: cache only the static SPA assets. Bypass cache for `/api/`
  (authenticated, dynamic).
- Note: Cloudflare is also a **reroute provider** in this app (Under-Attack mode,
  firewall/rate-limit rules). The Cloudflare account used to *front* the site and
  the one used to *mitigate* may differ — keep their API tokens separate. See
  [../skills/cloudflare-api.md](../skills/cloudflare-api.md).

See [../deploy/cloudflare/README.md](../deploy/cloudflare/README.md).

## Nginx (origin)

Example at [../deploy/nginx/rerouter.conf](../deploy/nginx/rerouter.conf). Key
points: serve `frontend/dist` as the document root with an SPA fallback to
`index.html`, proxy `location /api/` to `http://127.0.0.1:9277`, restore real
IP from Cloudflare and forward `CF-Connecting-IP` to the controller, and
**never** expose the controller on any other path or port.

## systemd

One unit (see [../deploy/systemd/](../deploy/systemd/)):

- `rerouter-controller.service` — the Rust binary, hardened, running as user
  `rerouter`. It serves the API, runs the alert dispatcher, and executes
  reroutes; there is no separate queue worker.

## Environment & config

Controller environment (template at
[../deploy/env/rerouter.example.env](../deploy/env/rerouter.example.env)):

- `DATABASE_URL` — MariaDB connection string;
- `REROUTER_CONFIG` — path to `/etc/rerouter/config.toml` (see
  [../backend-rust/config.example.toml](../backend-rust/config.example.toml));
- `SESSION_SECRET` — session cookie signing key;
- `SECRETS_KEY` — AES-256-GCM key for provider credentials at rest;
- `SMTP_HOST` / `SMTP_PORT` / `SMTP_USERNAME` / `SMTP_PASSWORD` / `SMTP_FROM`
  — email alert delivery;
- `TWO_FACTOR_ISSUER=Rerouter` — TOTP issuer string.

Secrets (provider API tokens, BGP keys) live in `/etc/rerouter/` owned by
`rerouter`, mode `0600`. Never commit secrets to Git.

## Install order

1. MariaDB: create `rerouter` database and user.
2. Controller: `cargo build --release`, install binary + config + env, enable
   the service. sqlx migrations run on startup (or explicitly via
   `rerouter-controller --migrate`).
3. Frontend: `npm ci && npm run build` in `frontend/`; deploy `frontend/dist`
   to the Nginx document root.
4. Nginx + Cloudflare origin cert; restrict origin to Cloudflare IPs.
5. Verify: SPA login + 2FA works end-to-end; `GET /api/health` returns OK
   through the proxy and on localhost.

Day-2 operations: [operations-runbook.md](operations-runbook.md).
