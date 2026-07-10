---
name: react-shadcn-spa
description: Patterns for the Rerouter SPA — Vite + React 19 + TypeScript + Tailwind + shadcn/ui, session-cookie auth with bound TOTP enrollment, credentialed fetch against /api, and token-bound reroute previews. Use for frontend/ work.
---

# Skill: React + Shadcn SPA (Rerouter frontend)

## Stack

- Vite + React 19 + TypeScript; Tailwind + shadcn/ui components.
- React Router for client-side routes; built to `frontend/dist` and served
  **statically by Nginx** — no SSR, no server runtime.
- All data via the controller's REST API under `/api/`, authenticated by the
  session cookie (see [rust-auth-2fa](rust-auth-2fa.md)).

## Routes

`/login` (password -> TOTP challenge; first-login enrollment code + TOTP),
`/dashboard`, `/devices`, `/devices/:id`,
`/devices/:deviceId/interfaces/:ifaceId`, `/flows`, `/rules`, `/templates`,
`/mitigations`, `/mitigations/manual`, `/alerts`, `/audit`, `/settings`, `/users`.

## API client (fetch wrapper)

- One typed wrapper around `fetch`: same-origin `/api/...` paths only,
  `credentials: 'include'`, JSON in/out, structured error type.
- CSRF safety comes from staying same-origin: never call the API cross-origin,
  never expose the session token to JS (it lives in an `HttpOnly` cookie).
- On `401`, clear auth state and redirect to `/login` (preserving the intended
  destination for post-login return).
- Dev: Vite proxies `/api` → `http://127.0.0.1:9277`, mirroring the production
  Nginx reverse proxy so cookies behave identically in dev and prod.

## Auth flow (context)

- An auth context/provider holds the current user, permissions, and the
  in-progress 2FA/enrollment challenge state.
- Login: `POST /api/auth/login` (password) → TOTP challenge →
  `POST /api/auth/totp` → session issued. First login walks through TOTP
  enrollment code, otpauth URI/QR, and confirmation code before app access.
- Recovery codes and newly issued enrollment codes are displayed exactly once;
  keep them in transient component state and never browser storage.
- Hide actions the user's permissions don't allow; the API enforces them
  regardless. See [authentication.md](../../docs/authentication.md).

## UI principles (Shadcn)

Never hide dangerous reroute details; render the **exact** reroute preview the
controller returns before a manual trigger, rule apply, or rollback — no
free-text box. Submit the matching one-use preview token only for the exact plan
the operator saw. Show telemetry freshness prominently
(live/stale/degraded/unknown), and show action history near rules and devices.
