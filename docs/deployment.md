# Deployment

Dev/prod target: Ubuntu 24.04. The site is fronted by **Cloudflare** at
`rerouter.cloudcraft.ro`; **Nginx** is the origin web server, serving the static
SPA build and reverse-proxying the API. The **Rust controller** runs as a
systemd service and binds its API to localhost only.

The released binary contains everything needed to bootstrap a server: an
installer (`--install`), embedded sqlx migrations and seeds, an embedded
`config.toml` template, and (optionally) the embedded SPA build.

## Quick install (single binary) — the primary path

Build the controller (the `embed-ui` cargo feature, **default off**, bakes the
SPA into the binary so it can serve the UI itself — see
[Single-binary UI](#single-binary-ui-embed-ui-feature) below):

```bash
# API-only binary (production — Nginx serves the SPA):
(cd backend-rust && cargo build --release)

# Single-binary with embedded UI (testing convenience):
(cd frontend && npm ci && npm run build) && \
  (cd backend-rust && cargo build --release --features embed-ui)
```

Copy it to the server and install:

```bash
scp backend-rust/target/release/rerouter-controller server:/tmp/
ssh server
sudo /tmp/rerouter-controller --install
```

`--install` is idempotent (re-running it just upgrades the binary and the
systemd unit — it **never overwrites** an existing `.env` or `config.toml`).
It:

1. creates the `rerouter` system user if missing (tolerated/warned if
   `useradd` is unavailable);
2. installs the binary to `/srv/rerouter/rerouter-controller` (mode `0755`);
3. writes `/srv/rerouter/.env` **only if it does not exist** (mode `0600`,
   owned by `rerouter`) — with `SESSION_SECRET` and `SECRETS_KEY` already
   filled in (32 random bytes hex each, generated at install time);
4. writes `/srv/rerouter/config.toml` **only if it does not exist** — an
   embedded copy of
   [../backend-rust/config.example.toml](../backend-rust/config.example.toml)
   (loopback bind `127.0.0.1:9277`, `operating_mode = "observe"`,
   `automatic_actions_enabled = false`);
5. writes `/etc/systemd/system/rerouter-controller.service` (overwrite
   allowed — the unit is ours), then `systemctl daemon-reload && systemctl
   enable rerouter-controller` (**enable, not start** — the `.env` needs
   filling first). If systemctl is unavailable (containers), it warns and
   prints manual instructions instead of erroring;
6. prints a next-steps summary.

For testing, `--install --prefix /tmp/x` installs under a prefix instead of
`/`.

Then:

**1. Fill in `/srv/rerouter/.env`.** Only `DATABASE_URL` and the `SMTP_*`
values need editing — the session/secret keys are auto-generated:

```bash
sudo vi /srv/rerouter/.env   # DATABASE_URL + SMTP_HOST/PORT/USERNAME/PASSWORD/FROM
```

**2. Create the MariaDB database and user** (matching `DATABASE_URL`):

```sql
CREATE DATABASE rerouter CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'rerouter'@'127.0.0.1' IDENTIFIED BY '<the password from .env>';
GRANT ALL PRIVILEGES ON rerouter.* TO 'rerouter'@'127.0.0.1';
FLUSH PRIVILEGES;
```

**3. Start and watch:**

```bash
sudo systemctl start rerouter-controller
journalctl -fu rerouter-controller
```

On startup the controller **preflights the DB credentials** (~5s timeout) and
exits with one clear, actionable error line on failure (host/db/user and why —
never the password), then **detects a fresh database and seeds it itself**:
it runs the embedded sqlx migrations (schema + roles/permissions + starter
templates + `system_settings` including `operating_mode = observe`) and logs
`fresh database — creating schema and seeds` / `schema up to date`. No manual
migration step is needed; `--migrate` and `--check-db` exist for explicit ops.

**4. Create the first admin:**

```bash
sudo -u rerouter /srv/rerouter/rerouter-controller \
  --config /srv/rerouter/config.toml --env-file /srv/rerouter/.env \
  --create-admin
```

Reads `ADMIN_EMAIL` / `ADMIN_NAME` / `ADMIN_PASSWORD` from flags or an
interactive prompt, Argon2id-hashes the password, inserts the user (idempotent
on email) with the `admin` role; TOTP 2FA enrollment happens at first login.

## CLI reference

```text
rerouter-controller
  --install [--prefix <dir>]  installer (prefix defaults to "/")
  --env-file <path>           .env to load (default /srv/rerouter/.env;
                              missing file = warning, not fatal)
  --config <path>             config.toml (default /srv/rerouter/config.toml;
                              missing file = built-in defaults mirroring
                              config.example.toml + a warning; REROUTER_CONFIG
                              env still respected)
  --check                     config check, then exit
  --check-db                  DB connectivity/credential check, then exit
  --migrate                   apply pending sqlx migrations, then exit
  --seed-templates            currently same as --migrate (seeds ship as migrations;
                              re-seeding deleted templates is a milestone-3 TODO)
  --create-admin              create the first admin user (needs a working DB);
                              --admin-email/--admin-name/--admin-password, or
                              ADMIN_EMAIL/ADMIN_NAME/ADMIN_PASSWORD env vars, or
                              interactive prompt
```

## Single-binary UI (`embed-ui` feature)

`cargo build --release --features embed-ui` (after building `frontend/dist`)
embeds the SPA in the binary; the controller then serves the UI at `/` with an
`index.html` fallback for client routes (`/api/*` always wins). This is a
**no-Nginx testing convenience**, not the production topology: the API bind
stays loopback-only, so reach it via an SSH tunnel:

```bash
ssh -L 9277:127.0.0.1:9277 server
# then browse http://127.0.0.1:9277
```

The default build (`cargo build --release`, feature off) stays green without
`frontend/dist`. In production, Nginx serves the SPA (next section).

## Topology (production)

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
- Note: in v1 Cloudflare is **only** the CDN/front for this site — it is **not** a
  reroute provider. Reroutes run as device-CLI templates over SSH to the routers;
  there is no Cloudflare (Under-Attack / firewall / rate-limit) mitigation path.

See [../deploy/cloudflare/README.md](../deploy/cloudflare/README.md).

## Nginx (origin)

Example at [../deploy/nginx/rerouter.conf](../deploy/nginx/rerouter.conf). Key
points: serve `frontend/dist` as the document root with an SPA fallback to
`index.html`, proxy `location /api/` to `http://127.0.0.1:9277`, restore real
IP from Cloudflare and forward `CF-Connecting-IP` to the controller, and
**never** expose the controller on any other path or port.

## systemd

One unit, written by `--install` to
`/etc/systemd/system/rerouter-controller.service` and mirrored verbatim at
[../deploy/systemd/rerouter-controller.service](../deploy/systemd/):

- `rerouter-controller.service` — the Rust binary, hardened
  (`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
  `ReadWritePaths=/srv/rerouter`), running as user `rerouter` from
  `/srv/rerouter` with `EnvironmentFile=/srv/rerouter/.env`. It serves the
  API, runs the alert dispatcher, and executes reroutes; there is no separate
  queue worker.

## Environment & config

Everything lives in `/srv/rerouter/`, owned by `rerouter`:

- `/srv/rerouter/rerouter-controller` — the binary;
- `/srv/rerouter/.env` — environment, mode `0600`, generated by `--install`
  with `SESSION_SECRET`/`SECRETS_KEY` pre-filled (reference copy:
  [../deploy/env/rerouter.example.env](../deploy/env/rerouter.example.env)):
  - `DATABASE_URL` — MariaDB connection string (**operator must fill**);
  - `SMTP_HOST` / `SMTP_PORT` / `SMTP_USERNAME` / `SMTP_PASSWORD` /
    `SMTP_FROM` — email alert delivery (**operator must fill**);
  - `SESSION_SECRET` — session cookie signing key (auto-generated);
  - `SECRETS_KEY` — AES-256-GCM key for device secrets at rest (SNMP
    communities, SSH passwords/keys) (auto-generated);
  - `TWO_FACTOR_ISSUER=Rerouter` — TOTP issuer string.
- `/srv/rerouter/config.toml` — controller config (see
  [../backend-rust/config.example.toml](../backend-rust/config.example.toml)).
  If the file is missing, the controller falls back to built-in defaults that
  exactly mirror `config.example.toml` and logs a warning.

The `.env` is loaded via `--env-file` (dotenvy); real process environment
always wins. Never commit secrets to Git, and never overwrite an operator's
`.env`/`config.toml`.

## Production install order

1. `rerouter-controller --install` (Quick install above): binary, `.env`,
   `config.toml`, systemd unit, service enabled.
2. Fill `/srv/rerouter/.env`; create the MariaDB database and user.
3. `systemctl start rerouter-controller` — the controller preflights the DB
   and migrates/seeds a fresh database itself.
4. Frontend: `npm ci && npm run build` in `frontend/`; deploy `frontend/dist`
   to the Nginx document root.
5. Nginx + Cloudflare origin cert; restrict origin to Cloudflare IPs.
6. Create the first admin (`--create-admin`); verify SPA login + 2FA works
   end-to-end; `GET /api/health` returns OK through the proxy and on
   localhost.

Day-2 operations: [operations-runbook.md](operations-runbook.md).
