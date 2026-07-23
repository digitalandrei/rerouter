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

**1. Fill in `/srv/rerouter/.env`.** `DATABASE_URL` is required. Configure
`SMTP_*` when email delivery is desired; Teams can be configured later in the UI.
The session/secret keys are auto-generated:

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
on email) with the `superadmin` role, and prints a separate one-time TOTP
enrollment code. Deliver that code out of band; the password alone cannot claim
the first authenticator.

## Release gate (local)

There is **no hosted CI** (owner decision, 2026-07-21). Before every release,
run the full gate locally and require all five commands to pass:

```bash
(cd backend-rust && cargo fmt --check)
(cd backend-rust && cargo clippy --all-targets -- -D warnings)
(cd backend-rust && DATABASE_URL="mysql://…/rerouter_test" cargo test --all-targets)
(cd frontend && npm run typecheck)
(cd frontend && npm run build)
```

The integration suites under `backend-rust/tests/` **skip silently when
`DATABASE_URL` is unset** — a green `cargo test` without a MariaDB test
database has not exercised reroute-guard, state-recovery, reachability, or
collector behavior. Point `DATABASE_URL` at a disposable MariaDB database
(the tests run migrations and write to it; never use the production DB).

Run `cargo audit` manually each audit cycle; accepted findings are recorded
in `plans/README.md`.

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
  --seed-templates            apply pending migrations containing seeds (does not
                              restore rows deleted after their migration ran)
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
- Reject every HTTP Host except `rerouter.cloudcraft.ro`. A Cloudflare source-IP
  list covers all Cloudflare customers; without an exact host guard, another
  proxied zone could point at the origin and reach the default virtual host.
- Run `sudo deploy/cloudflare/update-origin-ranges.sh`, then `sudo nginx -t`,
  before enabling the site. The generated, required include emits `allow` for
  every official IPv4/IPv6 range; the server block ends with `deny all`. Refresh
  it whenever Cloudflare changes its ranges.
- Because Cloudflare proxies, the **real client IP** arrives in
  `CF-Connecting-IP`. Keep Nginx's `$remote_addr` as the Cloudflare peer for the
  source ACL, then forward Cloudflare's header to the controller. Do not combine
  `real_ip_header` with the same server-level `allow` list: access checks would
  see the restored end-client address and deny valid traffic. The header is safe
  to trust after the Cloudflare-only ACL because only Nginx can reach the
  controller.
- Caching: cache only the static SPA assets. Bypass cache for `/api/`
  (authenticated, dynamic).
- Note: in v1 Cloudflare is **only** the CDN/front for this site — it is **not** a
  reroute provider. Reroutes run as device-CLI templates over SSH to the routers;
  there is no Cloudflare (Under-Attack / firewall / rate-limit) mitigation path.

See [../deploy/cloudflare/README.md](../deploy/cloudflare/README.md).

## Nginx (origin)

Example at [../deploy/nginx/rerouter.conf](../deploy/nginx/rerouter.conf). Key
points: serve `frontend/dist` as the document root with an SPA fallback to
`index.html`, proxy `location /api/` to `http://127.0.0.1:9277`, enforce the
Cloudflare source ACL and then forward `CF-Connecting-IP` to the controller, and
**never** expose the controller on any other path or port. The example also sets
HSTS, CSP, clickjacking/content-type protections, bounded proxy timeouts, and
no-cache for `index.html`. API responses carry `Cache-Control: no-store`, and the
proxy explicitly bypasses any configured Nginx cache.

## systemd

One unit, written by `--install` to
`/etc/systemd/system/rerouter-controller.service` and mirrored verbatim at
[../deploy/systemd/rerouter-controller.service](../deploy/systemd/rerouter-controller.service):

- `rerouter-controller.service` — the Rust binary, hardened
  (`NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `ProtectSystem=strict`,
  hidden `/proc`, a read-only application directory, empty capability sets,
  restricted address families/namespaces/syscalls and native syscall ABI only),
  running as user `rerouter` from
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
  exactly mirror `config.example.toml` and logs a warning. Unknown keys and
  invalid listener/safety combinations fail validation rather than being ignored.

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
   to the Nginx document root, then normalize its modes. Build output may inherit
   a restrictive umask, and Nginx returns `403` when `www-data` cannot traverse
   the document root or read `index.html`:

   ```bash
   WEB_ROOT=/var/www/rerouter/frontend/dist # Use the root from the active vhost.
   sudo find "$WEB_ROOT" -type d -exec chmod 0755 {} +
   sudo find "$WEB_ROOT" -type f -exec chmod 0644 {} +
   sudo -u www-data test -r "$WEB_ROOT/index.html"
   ```

   Repeat the read check after every frontend deployment and before reloading
   Nginx.
5. Nginx + Cloudflare origin cert; restrict origin to Cloudflare IPs.
6. Create the first superadmin (`--create-admin`); verify SPA login + 2FA works
   end-to-end; `GET /api/health` confirms process liveness and `GET /api/ready`
   confirms database readiness through the proxy and on localhost.

If the flow collector is enabled, separately allow UDP 2055 and/or 6343 only
from exporter management addresses. The web-origin Cloudflare allowlist does not
protect those UDP listeners; enforce router-to-collector ACL/uRPF controls.

Day-2 operations: [operations-runbook.md](operations-runbook.md).
