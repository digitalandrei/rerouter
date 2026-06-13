import { useEffect, useState, type FormEvent } from "react";
import { Activity, Copy, KeyRound, TerminalSquare } from "lucide-react";
import { toast } from "sonner";
import { api, type Device, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/confirm-dialog";

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

/** Cisco ASR (IOS) commands to enroll our public key under the SSH username, so
 *  the controller can authenticate by key. `key-string` takes the raw Base64 body
 *  (the middle field of the OpenSSH line), not the `ssh-rsa … comment` wrapper.
 *
 *  The body MUST be wrapped: a 2048-bit key is ~360 chars but the IOS terminal
 *  truncates input lines near 256, which yields "%SSH: Failed to decode the Key
 *  Value". IOS concatenates consecutive key-string lines until `exit`. */
function asrEnrollment(username: string, publicKey: string): string {
  const parts = publicKey.trim().split(/\s+/);
  const body = parts.length >= 2 ? parts[1] : publicKey.trim();
  const wrapped = (body.match(/.{1,72}/g) ?? [body]).map((l) => `   ${l}`);
  return [
    "configure terminal",
    " ip ssh pubkey-chain",
    `  username ${username || "rerouter"}`,
    "   key-string",
    ...wrapped,
    "   exit",
    "  exit",
    " end",
    "write memory",
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

          <label className="flex items-center gap-2 text-sm font-medium">
            <input type="checkbox" checked={form.enabled} onChange={(e) => setField("enabled", e.target.checked)} className="h-4 w-4 rounded border border-input" />
            Enabled (polling active)
          </label>

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
