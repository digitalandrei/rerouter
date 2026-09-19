/**
 * /settings — governed by docs/doctrine.md §8 (global safety switches),
 * docs/operations-runbook.md and docs/authentication.md.
 *
 * Hosts: operating mode (observe = read-only/alert-only, the shipped default;
 * enforce flips are admin-only and audited), the global automatic-reroute kill
 * switch (default OFF), and the global maintenance lock. Enabling automation or
 * clearing a lock is a deliberate, audited act — destructive styling, no
 * defaults that loosen safety.
 */
import { useEffect, useState } from "react";
import { X } from "lucide-react";
import { api, type SystemSettings, type RtbhCommunity, ApiError } from "@/lib/api";
import { humanizeToken } from "@/lib/labels";
import { useAuth } from "@/lib/auth";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { ConfirmDialog } from "@/components/confirm-dialog";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { NotificationsCard } from "./settings/notifications-card";

/** Global RTBH community catalog the blackhole templates pick from. */
function RtbhCard() {
  const { hasPermission } = useAuth();
  const canManage = hasPermission("manage_devices");
  const [items, setItems] = useState<RtbhCommunity[] | null>(null);
  const [label, setLabel] = useState("");
  const [community, setCommunity] = useState("");
  const [tag, setTag] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [removingId, setRemovingId] = useState<number | null>(null);

  function load() {
    setError(null);
    api.rtbh.list().then(setItems).catch((e) => {
      setItems(null);
      setError(e instanceof ApiError ? e.message : "Failed to load RTBH communities");
    });
  }
  useEffect(load, []);

  async function add() {
    setBusy(true);
    setError(null);
    try {
      const updated = await api.rtbh.create({
        label: label.trim(),
        community: community.trim(),
        tag: parseInt(tag, 10),
      });
      setItems(updated);
      setLabel("");
      setCommunity("");
      setTag("");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "failed to add");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-lg">RTBH communities</CardTitle>
        <CardDescription>
          Blackhole communities (standard <code>X:Y</code> or large{" "}
          <code>X:Y:Z</code>) plus the route tag the routers' RTBH redistribute
          route-map matches. The blackhole templates pick from this list.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {items === null ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : items.length === 0 ? (
          <p className="text-sm text-muted-foreground">None defined yet.</p>
        ) : (
          <div className="space-y-1">
            {items.map((c) => (
              <div
                key={c.id}
                className="flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm"
              >
                <span className="font-medium">{c.label}</span>
                <code className="text-xs">{c.community}</code>
                <Badge variant="outline">{humanizeToken(c.kind)}</Badge>
                <span className="text-xs text-muted-foreground">tag {c.tag}</span>
                <span className="flex-1" />
                {canManage && (
                  <Button
                    size="icon-sm"
                    variant="ghost"
                    className="text-destructive hover:text-destructive"
                    disabled={removingId !== null}
                    loading={removingId === c.id}
                    aria-label={`Remove RTBH community ${c.label}`}
                    onClick={() => {
                      setRemovingId(c.id); setError(null);
                      void api.rtbh.remove(c.id).then(load).catch((e) => setError(e instanceof ApiError ? e.message : "Failed to remove RTBH community")).finally(() => setRemovingId(null));
                    }}
                    title="Remove"
                  >
                    {removingId !== c.id && <X className="size-4" />}
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
        {canManage && (
          <div className="grid gap-2 sm:grid-cols-[1fr_1fr_110px_auto]">
            <Input placeholder="Label" value={label} disabled={busy} onChange={(e) => setLabel(e.target.value)} />
            <Input
              placeholder="65000:666"
              value={community}
              disabled={busy}
              onChange={(e) => setCommunity(e.target.value)}
            />
            <Input placeholder="Route tag" value={tag} disabled={busy} onChange={(e) => setTag(e.target.value)} />
            <Button size="sm" loading={busy} loadingLabel="Adding community…" onClick={() => void add()}>
              Add
            </Button>
          </div>
        )}
        {error && <p className="text-sm text-destructive">{error}</p>}
      </CardContent>
    </Card>
  );
}

export default function Settings() {
  const { user, hasPermission } = useAuth();
  const canAdmin = user?.roles.some((role) => role === "admin" || role === "superadmin") ?? false;
  const canManageLocks = hasPermission("manage_locks");
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);
  // Confirmation gate for the dangerous direction of a safety switch (the
  // control looks uniform now, so the deliberate/audited friction lives here).
  const [confirm, setConfirm] = useState<{
    title: string;
    description: string;
    confirmLabel: string;
    destructive: boolean;
    requireReauth?: boolean;
    run: (creds?: { password: string; totp_code: string }) => Promise<void>;
  } | null>(null);
  // Step-up credentials collected in the dialog when ARMING the system.
  const [reauthPw, setReauthPw] = useState("");
  const [reauthCode, setReauthCode] = useState("");
  const [reauthErr, setReauthErr] = useState<string | null>(null);

  function loadSettings() {
    setLoading(true);
    setLoadError(null);
    api.settings
      .get()
      .then(setSettings)
      .catch((e) => setLoadError(e instanceof ApiError ? e.message : "Failed to load settings"))
      .finally(() => setLoading(false));
  }

  useEffect(loadSettings, []);

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Settings</h1>

      {loading && (
        <p className="text-sm text-muted-foreground">Loading settings…</p>
      )}

      {!loading && loadError && <div role="alert" className="flex items-center gap-3 text-sm text-destructive"><span>Settings could not be loaded: {loadError}</span><Button size="sm" variant="outline" onClick={loadSettings}>Try again</Button></div>}
      {mutationError && <p role="alert" className="text-sm text-destructive">{mutationError}</p>}

      {settings && <Card>
        <CardHeader>
          <CardTitle className="text-lg">Operating mode</CardTitle>
          <CardDescription>
            <strong>observe</strong> (the shipped default) blocks autonomous reroutes.
            Authorized manual runs remain available after an exact server preview and explicit
            confirmation. Flipping to enforce is admin-only and audited.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <Switch
            checked={settings?.operating_mode === "enforce"}
            disabled={loading || settings === null || !canAdmin}
            aria-label="Toggle enforce mode"
            onCheckedChange={(v) => {
              if (v) {
                setConfirm({
                  title: "Switch to enforce mode?",
                  description:
                    "Enforce mode lets reroutes actually execute (still gated by every other safety rule). This flip is admin-only and audited.",
                  confirmLabel: "Switch to enforce",
                  destructive: true,
                  requireReauth: true,
                  run: (creds) =>
                    api.settings
                      .put({ operating_mode: "enforce", ...creds })
                      .then(setSettings),
                });
              } else {
                setMutationError(null); void api.settings.put({ operating_mode: "observe" }).then(setSettings).catch((e) => setMutationError(e instanceof ApiError ? e.message : "Failed to change operating mode"));
              }
            }}
          />
          <span className="text-sm font-medium">
            {settings?.operating_mode === "enforce"
              ? "Enforce — reroutes can execute"
              : "Observe — read-only / alert-only"}
          </span>
        </CardContent>
      </Card>}

      {settings && <Card>
        <CardHeader>
          <CardTitle className="text-lg">Automatic reroutes</CardTitle>
          <CardDescription>
            Global master switch for <strong>automatic</strong> reroutes (default
            OFF, admin-only and audited). Automatic execution requires{" "}
            <strong>all</strong> of: enforce mode, this switch ON, and the firing
            rule's own <strong>Auto</strong> toggle — plus the executor's device
            locks &amp; cooldowns. Previewed, explicitly confirmed manual reroutes
            remain available in either operating mode.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <Switch
            checked={!!settings?.automatic_actions_enabled}
            disabled={loading || settings === null || !canAdmin}
            aria-label="Toggle automatic reroutes"
            onCheckedChange={(v) => {
              if (v) {
                setConfirm({
                  title: "Enable automatic reroutes globally?",
                  description:
                    "With enforce mode on and a rule's own Auto toggle on, a firing rule will execute its reroute with no operator. Admin-only and audited.",
                  confirmLabel: "Enable automatic reroutes",
                  destructive: true,
                  requireReauth: true,
                  run: (creds) =>
                    api.settings
                      .put({ automatic_actions_enabled: true, ...creds })
                      .then(setSettings),
                });
              } else {
                setMutationError(null); void api.settings
                  .put({ automatic_actions_enabled: false })
                  .then(setSettings).catch((e) => setMutationError(e instanceof ApiError ? e.message : "Failed to disable automatic reroutes"));
              }
            }}
          />
          <span className="text-sm font-medium">
            {settings?.automatic_actions_enabled
              ? "Automatic reroutes enabled"
              : "Automatic reroutes disabled"}
          </span>
        </CardContent>
      </Card>}

      {settings && <Card>
        <CardHeader>
          <CardTitle className="text-lg">Global maintenance lock</CardTitle>
          <CardDescription>
            While locked, no reroute actions run at all (manage_locks).
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <Switch
            checked={!!settings?.global_lock}
            disabled={loading || settings === null || !canManageLocks}
            aria-label="Toggle maintenance lock"
            onCheckedChange={(v) => {
              if (v) {
                setMutationError(null); void api.settings.put({ global_lock: true }).then(setSettings).catch((e) => setMutationError(e instanceof ApiError ? e.message : "Failed to engage maintenance lock"));
              } else {
                setConfirm({
                  title: "Clear the maintenance lock?",
                  description:
                    "Clearing the lock re-allows reroute actions to run.",
                  confirmLabel: "Clear lock",
                  destructive: false,
                  run: () =>
                    api.settings.put({ global_lock: false }).then(setSettings),
                });
              }
            }}
          />
          <span className="text-sm font-medium">
            {settings?.global_lock
              ? "Maintenance lock engaged — all reroutes blocked"
              : "No maintenance lock"}
          </span>
        </CardContent>
      </Card>}

      <RtbhCard />

      <NotificationsCard />

      {confirm && (
        <ConfirmDialog
          open
          onOpenChange={(v) => {
            if (!v) {
              setConfirm(null);
              setReauthPw("");
              setReauthCode("");
              setReauthErr(null);
            }
          }}
          title={confirm.title}
          description={
            <>
              {confirm.description}
              {confirm.requireReauth && (
                <div className="mt-3 space-y-2">
                  <p className="text-sm font-medium text-foreground">
                    Confirm it's you — arming the system requires your password and
                    a current authenticator code.
                  </p>
                  <Input
                    type="password"
                    autoComplete="current-password"
                    placeholder="Your password"
                    value={reauthPw}
                    onChange={(e) => setReauthPw(e.target.value)}
                  />
                  <Input
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    placeholder="6-digit authenticator code"
                    value={reauthCode}
                    onChange={(e) => setReauthCode(e.target.value)}
                  />
                  {reauthErr && (
                    <p className="text-sm text-destructive">{reauthErr}</p>
                  )}
                </div>
              )}
            </>
          }
          confirmLabel={confirm.confirmLabel}
          destructive={confirm.destructive}
          onConfirm={async () => {
            setReauthErr(null);
            const creds = confirm.requireReauth
              ? { password: reauthPw, totp_code: reauthCode }
              : undefined;
            try {
              await confirm.run(creds);
            } catch (e) {
              const msg = e instanceof ApiError ? e.message : "request failed";
              setReauthErr(
                msg === "reauth_required"
                  ? "Enter your password and authenticator code."
                  : msg === "reauth_failed"
                    ? "Password or authenticator code is incorrect."
                    : msg === "reauth_totp_reused"
                      ? "That code was just used to sign in. Wait for your authenticator to show the next code, then retry."
                      : msg,
              );
              return; // keep the dialog open so the operator can retry
            }
            setConfirm(null);
            setReauthPw("");
            setReauthCode("");
          }}
        />
      )}
    </div>
  );
}
