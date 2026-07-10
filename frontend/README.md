# Rerouter Frontend

Operational SPA for the Rerouter controller: Vite, React 19, TypeScript,
Tailwind, and shadcn-style components. Production builds are static files served
by Nginx; same-origin credentialed requests reach the loopback Rust API through
`/api/`.

See [doctrine](../docs/doctrine.md), [authentication](../docs/authentication.md),
and the [reroute engine](../docs/reroute-engine.md) before changing an execution
workflow.

## Development

```sh
npm ci
npm run dev
npm run typecheck
npm run build
npm audit
```

The Vite dev proxy mirrors Nginx and points `/api` to `127.0.0.1:9277`. Session
state is owned by the controller in an `HttpOnly` cookie.

## Layout

- `src/lib/api.ts`: typed API contract and credentialed fetch wrapper.
- `src/lib/auth.tsx`: password, TOTP/enrollment-code challenge, recovery-code
  display, session, and RBAC helpers.
- `src/components/ui/`: shared controls.
- `src/pages/`: dashboard, devices/interfaces, rules, templates, mitigations,
  alerts, audit, settings, and users.

Routes include `/login`, `/dashboard`, `/devices`, device/interface details,
`/rules`, `/templates`, `/mitigations`, `/mitigations/manual`, `/audit`,
`/settings`, and `/users`.

## Safety UI

- Render plans returned by the execution endpoint, including verification and
  rollback commands. Generic template rendering is not an execution preview.
- Enforce-mode manual actions, firing-rule applies, and rollbacks must return and
  then consume the server's one-time `preview_token`.
- Show observe/enforce or unknown mode truthfully. Never present stale telemetry
  as live or a sent command as successful.
- Treat UI gating as usability. RBAC, target validation, locks, cooldowns,
  preview binding, persistence, and verification remain server boundaries.
