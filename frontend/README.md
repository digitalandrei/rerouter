# Rerouter — Frontend (React + Shadcn SPA)

Operational dashboard for the Rerouter control plane. A standalone
Vite + React 18 + TypeScript + Tailwind + shadcn-style single-page app,
built to `dist/` and served **statically by Nginx**. It talks to the
`rerouter-controller` REST API under `/api/` with same-origin credentialed
fetch (session cookie); the controller binds to `127.0.0.1:9277` and is
reachable only through the Nginx reverse proxy behind Cloudflare.

See [../docs/doctrine.md](../docs/doctrine.md) §5.3 for UI principles, the
[frontend-agent](../agents/frontend-agent.md), and the
[react-shadcn-spa](../skills/react-shadcn-spa.md) skill.

## Development

```sh
npm install
npm run dev      # Vite dev server; proxies /api -> http://127.0.0.1:9277
npm run build    # type-check + build static assets into dist/
npm run preview  # serve the production build locally
```

The dev proxy in [vite.config.ts](vite.config.ts) mirrors the production
Nginx `location /api/` block, so auth cookies and fetch calls behave
identically in both environments. There is no separate frontend auth state
to configure: the session is an HttpOnly cookie owned by the controller.

## Layout

- [src/lib/api.ts](src/lib/api.ts) — typed fetch wrapper for the canonical
  `/api` endpoints (`credentials: 'include'`, JSON, 401 → redirect to
  `/login`).
- [src/lib/auth.tsx](src/lib/auth.tsx) — auth context: password →
  TOTP challenge → session; `reauth()` for high-safety reroutes.
- [src/components/ui/](src/components/ui/) — shadcn-style components
  (button, card, badge) with the `cn()` util in
  [src/lib/utils.ts](src/lib/utils.ts).
- [src/pages/](src/pages/) — one file per route.

## Pages (per doctrine)

`/login` (password step → TOTP step; first-login TOTP enrollment),
`/dashboard`, `/assets`, `/assets/:id`, `/providers`, `/rules`,
`/reroutes`, `/reroutes/manual`, `/alerts`, `/audit`, `/settings`.

## UI principles

- Never hide dangerous reroute details; show the exact reroute preview
  (template, asset/prefix, provider, method, resolved parameters).
- High-safety reroutes require fresh re-auth (password + TOTP), typed
  confirmation, and a reason — the API enforces this; the SPA renders it.
- Show asset/provider reachability and telemetry freshness prominently
  (live / cached / degraded / unknown).
- Surface `uncertain` reroute actions so they are impossible to miss; never
  display "sent" as success.
- Show action history near each rule and asset.
- Drag-and-drop monitored-asset builder.
- The SPA is presentation only: every safety rule (allowlisted templates,
  locks, cooldowns, RBAC) is enforced by the controller. UI gating is UX,
  not security.
