---
name: react-shadcn-spa
description: Patterns for the Rerouter SPA — Vite + React 18 + TypeScript + Tailwind + shadcn/ui, session-cookie auth with the TOTP challenge flow, credentialed fetch against /api, and safety-first UI for reroutes. Use for frontend/ work.
---

# Skill: React + Shadcn SPA (Rerouter frontend)

## Stack

- Vite + React 18 + TypeScript; Tailwind + shadcn/ui components.
- React Router for client-side routes; built to `frontend/dist` and served
  **statically by Nginx** — no SSR, no server runtime.
- All data via the controller's REST API under `/api/`, authenticated by the
  session cookie (see [rust-auth-2fa](rust-auth-2fa.md)).

## Routes

`/login` (password → TOTP challenge; first-login TOTP enrollment), `/dashboard`,
`/assets`, `/assets/:id`, `/providers`, `/rules`, `/reroutes`, `/reroutes/manual`,
`/alerts`, `/audit`, `/settings`.

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
  in-progress 2FA challenge state.
- Login: `POST /api/auth/login` (password) → TOTP challenge →
  `POST /api/auth/totp` → session issued. First login walks through TOTP
  enrollment (QR + confirm code) before any app access.
- High-safety reroutes prompt **fresh re-auth** (`POST /api/auth/reauth`,
  password + current TOTP) immediately before submission.
- Hide actions the user's permissions don't allow; the API enforces them
  regardless. See [../docs/authentication.md](../docs/authentication.md).

## UI principles (Shadcn)

Never hide dangerous reroute details; render the **exact** reroute preview the
controller returns before a manual trigger — no free-text box. Show telemetry
freshness badges prominently (live/cached/degraded/unknown). Require **typed
confirmation** plus a reason for high-safety actions. Show action history near
each rule and asset. Drag-and-drop builder for monitored assets.
