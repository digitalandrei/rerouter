import { useEffect, useState, type FormEvent } from "react";
import { Activity, Copy, KeyRound, ShieldCheck, TerminalSquare } from "lucide-react";
import { toast } from "sonner";
import { api, type Device, type CapabilityCheck, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { ToneBadge } from "@/components/status-badge";

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

interface Form {
  name: string;
  hostname: string;
  snmp_port: string;
  poll_interval_seconds: string;
  enabled: boolean;
  community: string;
  ssh_auth_method: string; // "none" | "password" | "key"
  ssh_username: string;
  ssh_port: string;
  ssh_password: string;
  ssh_private_key: string;
  ssh_key_passphrase: string;
}

function build(device: Device): Form {
  return {
    name: device.name,
    hostname: device.hostname,
    snmp_port: String(device.snmp_port),
    poll_interval_seconds: String(device.poll_interval_seconds),
    enabled: device.enabled,
    community: "",
    ssh_auth_method: device.ssh_auth_method ?? "none",
    ssh_username: device.ssh_username ?? "",
    ssh_port: String(device.ssh_port ?? 22),
    ssh_password: "",
    ssh_private_key: "",
    ssh_key_passphrase: "",
  };
}

/** Wrap an OpenSSH public key's Base64 body for IOS `key-string`: ≤72-char,
 *  3-space-indented lines. `key-string` takes the raw Base64 body (the middle
 *  field of the OpenSSH line), not the `ssh-rsa … comment` wrapper, and it MUST
 *  be wrapped — a 2048-bit key is ~360 chars but the IOS terminal truncates input
 *  near 256 ("%SSH: Failed to decode the Key Value"). IOS concatenates
 *  consecutive key-string lines until `exit`. */
function wrapKeyString(publicKey: string): string[] {
  const parts = publicKey.trim().split(/\s+/);
  const body = parts.length >= 2 ? parts[1] : publicKey.trim();
  return (body.match(/.{1,72}/g) ?? [body]).map((l) => `   ${l}`);
}

/** Cisco ASR (IOS) commands to enroll our public key under the SSH username, so
 *  the controller can authenticate by key. Key-only — for a fresh account that
 *  also needs the user + restricted view, use `fullRouterSetup`. */
function asrEnrollment(username: string, publicKey: string): string {
  return [
    "configure terminal",
    " ip ssh pubkey-chain",
    `  username ${username || "rerouter"}`,
    "   key-string",
    ...wrapKeyString(publicKey),
    "   exit",
    "  exit",
    " end",
    "write memory",
  ].join("\n");
}

/** The RRT parser-view command grants, by mode — exactly the commands Rerouter
 *  sends. Shared by the standalone view snippet and the full-setup snippet so the
 *  two never drift. Mirrors deploy/cisco/rerouter-view.ios. */
const RRT_VIEW_BODY = ` ! reads: connectivity, template verification + discovery
 commands exec include terminal length 0
 commands exec include show clock
 commands exec include show version
 commands exec include show ip route
 commands exec include show ipv6 route
 commands exec include show ip bgp
 commands exec include show interfaces
 commands exec include show running-config
 ! BGP soft-clear (activate advertise / route-map change)
 commands exec include clear ip bgp
 ! enter global configuration mode
 commands exec include configure terminal
 ! blackhole / null-route to Null0 (IPv4 + IPv6)
 commands configure include ip route
 commands configure include no ip route
 commands configure include ipv6 route
 commands configure include no ipv6 route
 ! BGP advertise via outbound prefix-list
 commands configure include ip prefix-list
 commands configure include no ip prefix-list
 ! BGP session shut/no-shut + route-map change
 commands configure include router bgp
 commands router include neighbor
 commands router include no neighbor
 ! interface MSS clamp + shut/no-shut
 commands configure include interface
 commands interface include ip tcp adjust-mss
 commands interface include no ip tcp adjust-mss
 commands interface include shutdown
 commands interface include no shutdown
 ! uncomment so 'show run' also reveals 'network' statements (prefix discovery):
 ! commands router include network`;

/** The built-in Cisco IOS parser view that limits the controller's account to
 *  exactly the commands Rerouter issues. Also kept in the repo at
 *  deploy/cisco/rerouter-view.ios; surfaced here so it's installable from the
 *  UI. Secrets are placeholders the operator fills in. */
const RRT_VIEW = `! Restricted parser view for the Rerouter SSH account.
! Replace <ENABLE_SECRET> and <VIEW_SECRET>. Bind to the local account with
! 'username <user> view RRT secret <...>'; verify with 'enable view RRT'.
configure terminal
 aaa new-model
 aaa authentication login default local
 aaa authorization exec default local
 enable secret <ENABLE_SECRET>
end
enable view
configure terminal
parser view RRT
 secret <VIEW_SECRET>
${RRT_VIEW_BODY}
end`;

/** Full first-time router setup for the controller's SSH account: AAA, the RRT
 *  restricted view, the local user bound to that view, and our public key for key
 *  auth. SSH itself is assumed already enabled (the controller reaches the device
 *  now), so this never touches the host key / crypto. */
function fullRouterSetup(username: string, publicKey: string): string {
  const user = username || "rerouter";
  return [
    `! Full Rerouter setup for the SSH account "${user}" on this router.`,
    `! SSH is assumed already enabled (the controller reaches this device now), so`,
    `! the host key / crypto is left untouched. Replace every <...> placeholder.`,
    `! REVIEW before pasting: 'aaa new-model' changes how all logins are authorized.`,
    ``,
    `! 1. AAA — local authentication + exec authorization (applies the view on login)`,
    `configure terminal`,
    ` aaa new-model`,
    ` aaa authentication login default local`,
    ` aaa authorization exec default local`,
    ` enable secret <ENABLE_SECRET>`,
    `end`,
    ``,
    `! 2. The restricted RRT view (exactly the commands Rerouter sends)`,
    `enable view`,
    `configure terminal`,
    `parser view RRT`,
    ` secret <VIEW_SECRET>`,
    RRT_VIEW_BODY,
    `end`,
    ``,
    `! 3. The "${user}" account, bound to the RRT view (the secret is a fallback;`,
    `!    the controller authenticates with the key below, not this password)`,
    `configure terminal`,
    ` username ${user} view RRT secret <USER_SECRET>`,
    `end`,
    ``,
    `! 4. Install the controller's public key for "${user}" (key auth)`,
    `configure terminal`,
    ` ip ssh pubkey-chain`,
    `  username ${user}`,
    `   key-string`,
    ...wrapKeyString(publicKey),
    `   exit`,
    `  exit`,
    ` end`,
    ``,
    `! 5. Ensure the vty lines accept SSH with local login`,
    `configure terminal`,
    ` line vty 0 15`,
    `  transport input ssh`,
    `  login local`,
    `end`,
    `write memory`,
  ].join("\n");
}

/** Device settings tab: rename / hostname / SNMP / SSH credentials, plus the
 *  Test SNMP and Test SSH probes. manage_devices only (gated by the caller). */
export function DeviceSettingsTab({ device, onSaved }: { device: Device; onSaved: () => void }) {
  const [form, setForm] = useState<Form>(() => build(device));
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [regenOpen, setRegenOpen] = useState(false);
  const [checking, setChecking] = useState(false);
  const [caps, setCaps] = useState<CapabilityCheck[] | null>(null);
  const [capsErr, setCapsErr] = useState<string | null>(null);

  // Reset only when navigating to a different device (not on the 30s refresh of
  // the same device, which would wipe in-progress edits).
  useEffect(() => {
    setForm(build(device));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device.id]);

  function setField<K extends keyof Form>(field: K, value: Form[K]) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const payload: Record<string, unknown> = {
        name: form.name.trim(),
        hostname: form.hostname.trim(),
        snmp_port: parseInt(form.snmp_port, 10),
        poll_interval_seconds: parseInt(form.poll_interval_seconds, 10),
        enabled: form.enabled,
      };
      if (form.community.trim()) payload.community = form.community.trim();
      if (form.ssh_auth_method !== "none") {
        payload.ssh_auth_method = form.ssh_auth_method;
        if (form.ssh_username.trim()) payload.ssh_username = form.ssh_username.trim();
        if (form.ssh_port) payload.ssh_port = parseInt(form.ssh_port, 10);
        if (form.ssh_auth_method === "password" && form.ssh_password)
          payload.ssh_password = form.ssh_password;
        if (form.ssh_auth_method === "key" && form.ssh_private_key)
          payload.ssh_private_key = form.ssh_private_key;
        if (form.ssh_key_passphrase) payload.ssh_key_passphrase = form.ssh_key_passphrase;
      }
      await api.devices.update(device.id, payload);
      toast.success("Device updated");
      onSaved();
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Failed to update device");
    } finally {
      setBusy(false);
    }
  }

  async function generateKey() {
    setGenerating(true);
    try {
      const r = await api.devices.generateKey(device.id);
      toast.success("SSH key pair generated", {
        description: "Enroll the new public key on the router, then Test SSH.",
      });
      // Reflect the new pubkey + key-auth method immediately.
      setForm((f) => ({ ...f, ssh_auth_method: "key", ssh_private_key: "", ssh_key_passphrase: "" }));
      onSaved();
      return r;
    } catch (err) {
      toast.error(err instanceof ApiError ? err.message : "Key generation failed");
    } finally {
      setGenerating(false);
    }
  }

  async function checkAccess() {
    setChecking(true);
    setCaps(null);
    setCapsErr(null);
    try {
      const r = await api.devices.sshCapabilities(device.id);
      if (r.ok && r.checks) setCaps(r.checks);
      else setCapsErr(r.error ?? "probe failed");
    } catch {
      setCapsErr("probe request failed");
    } finally {
      setChecking(false);
    }
  }

  function copy(text: string, what: string) {
    void navigator.clipboard
      .writeText(text)
      .then(() => toast.success(`${what} copied`))
      .catch(() => toast.error("Copy failed"));
  }

  async function testSnmp() {
    setTesting(true);
    try {
      const r = await api.devices.test(device.id);
      if (r.ok) toast.success(`SNMP OK: ${[r.vendor, r.model].filter(Boolean).join(" / ") || "reachable"}`);
      else toast.error(`SNMP failed: ${r.error ?? "unknown"}`);
    } catch {
      toast.error("SNMP test failed");
    } finally {
      setTesting(false);
    }
  }

  async function testSsh() {
    setTesting(true);
    try {
      const r = await api.devices.sshTest(device.id);
      if (r.ok) {
        toast.success(`SSH OK${r.pinned_now ? " — host key pinned" : ""}`, {
          description: r.fingerprint ?? undefined,
        });
      } else {
        toast.error(`SSH failed: ${r.error ?? "unknown"}`);
      }
    } catch {
      toast.error("SSH test failed");
    } finally {
      setTesting(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Device settings</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={save} className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="block space-y-1 text-sm font-medium">
              Name
              <input required className={inputClass} value={form.name} onChange={(e) => setField("name", e.target.value)} />
            </label>
            <label className="block space-y-1 text-sm font-medium">
              Hostname / IP
              <input required className={inputClass} value={form.hostname} onChange={(e) => setField("hostname", e.target.value)} />
            </label>
            <label className="block space-y-1 text-sm font-medium">
              SNMP port
              <input type="number" min={1} max={65535} required className={inputClass} value={form.snmp_port} onChange={(e) => setField("snmp_port", e.target.value)} />
            </label>
            <label className="block space-y-1 text-sm font-medium">
              Poll interval (seconds)
              <input type="number" min={10} required className={inputClass} value={form.poll_interval_seconds} onChange={(e) => setField("poll_interval_seconds", e.target.value)} />
            </label>
          </div>

          <div className="flex items-center gap-3 text-sm font-medium">
            <Switch
              id="device-enabled"
              checked={form.enabled}
              onCheckedChange={(v) => setField("enabled", v)}
              aria-label="Toggle polling"
            />
            <label htmlFor="device-enabled">Enabled (polling active)</label>
          </div>

          <label className="block space-y-1 text-sm font-medium">
            SNMP community string
            <input className={inputClass} value={form.community} onChange={(e) => setField("community", e.target.value)} placeholder="leave blank to keep stored value" autoComplete="off" />
          </label>

          <div className="space-y-4 rounded-md border border-border p-4">
            <label className="block space-y-1 text-sm font-medium">
              SSH authentication
              <select className={inputClass} value={form.ssh_auth_method} onChange={(e) => setField("ssh_auth_method", e.target.value)}>
                <option value="none">none</option>
                <option value="password">password</option>
                <option value="key">key</option>
              </select>
            </label>
            {form.ssh_auth_method !== "none" && (
              <>
                <div className="grid gap-4 sm:grid-cols-2">
                  <label className="block space-y-1 text-sm font-medium">
                    SSH username
                    <input className={inputClass} value={form.ssh_username} onChange={(e) => setField("ssh_username", e.target.value)} placeholder="leave blank to keep" autoComplete="off" />
                  </label>
                  <label className="block space-y-1 text-sm font-medium">
                    SSH port
                    <input type="number" min={1} max={65535} className={inputClass} value={form.ssh_port} onChange={(e) => setField("ssh_port", e.target.value)} />
                  </label>
                </div>
                {form.ssh_auth_method === "password" && (
                  <label className="block space-y-1 text-sm font-medium">
                    SSH password
                    <input type="password" className={inputClass} value={form.ssh_password} onChange={(e) => setField("ssh_password", e.target.value)} placeholder="leave blank to keep stored password" autoComplete="new-password" />
                  </label>
                )}
                {form.ssh_auth_method === "key" && (
                  <div className="space-y-4">
                    {/* Generate / regenerate an in-app RSA key pair (no passphrase).
                        The private key is stored encrypted; the public key is shown
                        below for enrollment on the router. */}
                    <div className="flex flex-wrap items-center gap-2">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        disabled={generating}
                        onClick={() => {
                          if (device.ssh_public_key || device.ssh_configured) setRegenOpen(true);
                          else void generateKey();
                        }}
                      >
                        <KeyRound className="size-4" />
                        {generating
                          ? "Generating…"
                          : device.ssh_public_key
                            ? "Regenerate key pair"
                            : "Generate key pair"}
                      </Button>
                      <span className="text-xs text-muted-foreground">
                        2048-bit RSA, no passphrase. Private key stored encrypted.
                      </span>
                    </div>

                    {device.ssh_public_key && (
                      <div className="space-y-3 rounded-md border border-border p-3">
                        <div className="space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                              Public key
                            </span>
                            <Button type="button" variant="ghost" size="sm" onClick={() => copy(device.ssh_public_key!, "Public key")}>
                              <Copy className="size-3.5" />
                              Copy
                            </Button>
                          </div>
                          <pre className="overflow-x-auto rounded bg-muted/40 p-2 font-mono text-[11px] leading-relaxed break-all whitespace-pre-wrap">
                            {device.ssh_public_key}
                          </pre>
                        </div>
                        <div className="space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                              Enroll on Cisco ASR
                            </span>
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => copy(asrEnrollment(device.ssh_username ?? form.ssh_username, device.ssh_public_key!), "Enrollment commands")}
                            >
                              <Copy className="size-3.5" />
                              Copy
                            </Button>
                          </div>
                          <pre className="overflow-x-auto rounded bg-muted/40 p-2 font-mono text-[11px] leading-relaxed">
                            {asrEnrollment(device.ssh_username ?? form.ssh_username, device.ssh_public_key)}
                          </pre>
                          <p className="text-xs text-muted-foreground">
                            Run these on the router, then use <strong>Test SSH</strong> to confirm key auth.
                          </p>
                        </div>
                        {/* One-stop bootstrap for a fresh router: account + this key + RRT view. */}
                        <details className="rounded-md border border-border p-3">
                          <summary className="flex cursor-pointer items-center justify-between text-sm font-medium">
                            Full router setup (account + key + view)
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() =>
                                copy(
                                  fullRouterSetup(device.ssh_username ?? form.ssh_username, device.ssh_public_key!),
                                  "Router setup",
                                )
                              }
                            >
                              <Copy className="size-3.5" />
                              Copy
                            </Button>
                          </summary>
                          <p className="mt-2 text-xs text-muted-foreground">
                            First-time bootstrap for a fresh router: creates the{" "}
                            <code>{device.ssh_username ?? "rerouter"}</code> account, installs this public key, and
                            applies the least-privilege RRT view. Fill in the <code>&lt;…SECRET&gt;</code> placeholders;
                            SSH must already be enabled.
                          </p>
                          <pre className="mt-2 overflow-x-auto rounded bg-muted/40 p-2 font-mono text-[11px] leading-relaxed">
                            {fullRouterSetup(device.ssh_username ?? form.ssh_username, device.ssh_public_key)}
                          </pre>
                        </details>
                      </div>
                    )}

                    <details className="rounded-md border border-border p-3">
                      <summary className="cursor-pointer text-sm font-medium">
                        Or paste your own private key
                      </summary>
                      <div className="mt-3 space-y-4">
                        <label className="block space-y-1 text-sm font-medium">
                          SSH private key
                          <textarea rows={5} className={`${inputClass} font-mono text-xs`} value={form.ssh_private_key} onChange={(e) => setField("ssh_private_key", e.target.value)} placeholder="leave blank to keep stored key" />
                        </label>
                        <label className="block space-y-1 text-sm font-medium">
                          Key passphrase
                          <input type="password" className={inputClass} value={form.ssh_key_passphrase} onChange={(e) => setField("ssh_key_passphrase", e.target.value)} placeholder="leave blank to keep" autoComplete="new-password" />
                        </label>
                        <p className="text-xs text-muted-foreground">
                          Saving a pasted key replaces the stored one; its public key is shown above after saving.
                        </p>
                      </div>
                    </details>
                  </div>
                )}

                {/* Command-access check — does this account have permission to run
                    what Rerouter needs? Read-only probe (changes nothing). */}
                <div className="space-y-2 rounded-md border border-border p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium">Command access</span>
                    <Button type="button" variant="outline" size="sm" disabled={checking} onClick={() => void checkAccess()}>
                      <ShieldCheck className="size-4" />
                      {checking ? "Checking…" : "Check access"}
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Verifies the SSH account can run the commands Rerouter needs (config reads + entering config mode). Changes nothing on the router.
                  </p>
                  {capsErr && (
                    <p className="text-sm text-destructive" role="alert">
                      {capsErr}
                    </p>
                  )}
                  {caps && (
                    <ul className="space-y-1.5">
                      {caps.map((c) => (
                        <li key={c.command} className="flex items-start gap-2 text-sm">
                          <ToneBadge tone={c.ok ? "good" : "bad"}>{c.ok ? "OK" : "denied"}</ToneBadge>
                          <div className="min-w-0 flex-1">
                            <div>{c.name}</div>
                            <code className="text-xs break-all text-muted-foreground">{c.command}</code>
                            {!c.ok && c.detail && (
                              <div className="break-all text-xs text-destructive">{c.detail}</div>
                            )}
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                  {caps && caps.some((c) => !c.ok) && (
                    <p className="text-xs text-muted-foreground">
                      Denied commands usually mean the account's privilege level or parser view is too restrictive. Install the restricted view below.
                    </p>
                  )}

                  <details className="rounded-md border border-border p-3">
                    <summary className="flex cursor-pointer items-center justify-between text-sm font-medium">
                      Restricted IOS view (RRT)
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        onClick={(e) => {
                          e.preventDefault();
                          copy(RRT_VIEW, "View config");
                        }}
                      >
                        <Copy className="size-3.5" />
                        Copy
                      </Button>
                    </summary>
                    <p className="mt-2 text-xs text-muted-foreground">
                      A Cisco parser view that limits this account to exactly the commands Rerouter sends. Replace the two secrets; bind it to the account with <code>username &lt;user&gt; view RRT secret …</code>, or test locally with <code>enable view RRT</code>.
                    </p>
                    <pre className="mt-2 overflow-x-auto rounded bg-muted/40 p-2 font-mono text-[11px] leading-relaxed">
                      {RRT_VIEW}
                    </pre>
                  </details>
                </div>
              </>
            )}
          </div>

          <div className="flex flex-wrap gap-2">
            <Button type="submit" disabled={busy}>
              {busy ? "Saving…" : "Save changes"}
            </Button>
            <Button type="button" variant="outline" disabled={testing} onClick={() => void testSnmp()}>
              <Activity className="size-4" />
              Test SNMP
            </Button>
            <Button type="button" variant="outline" disabled={testing} onClick={() => void testSsh()}>
              <TerminalSquare className="size-4" />
              Test SSH
            </Button>
          </div>
        </form>
      </CardContent>

      <ConfirmDialog
        open={regenOpen}
        onOpenChange={setRegenOpen}
        title="Regenerate SSH key pair?"
        description="This replaces the stored private key. Key authentication will FAIL until you enroll the new public key on the router. The old key is discarded and cannot be recovered."
        confirmLabel="Regenerate"
        onConfirm={async () => {
          setRegenOpen(false);
          await generateKey();
        }}
      />
    </Card>
  );
}
