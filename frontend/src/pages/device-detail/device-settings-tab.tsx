import { useEffect, useState, type FormEvent } from "react";
import { Activity, TerminalSquare } from "lucide-react";
import { toast } from "sonner";
import { api, type Device, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

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

/** Device settings tab: rename / hostname / SNMP / SSH credentials, plus the
 *  Test SNMP and Test SSH probes. manage_devices only (gated by the caller). */
export function DeviceSettingsTab({ device, onSaved }: { device: Device; onSaved: () => void }) {
  const [form, setForm] = useState<Form>(() => build(device));
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);

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
                    <label className="block space-y-1 text-sm font-medium">
                      SSH private key
                      <textarea rows={5} className={`${inputClass} font-mono text-xs`} value={form.ssh_private_key} onChange={(e) => setField("ssh_private_key", e.target.value)} placeholder="leave blank to keep stored key" />
                    </label>
                    <label className="block space-y-1 text-sm font-medium">
                      Key passphrase
                      <input type="password" className={inputClass} value={form.ssh_key_passphrase} onChange={(e) => setField("ssh_key_passphrase", e.target.value)} placeholder="leave blank to keep" autoComplete="new-password" />
                    </label>
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
    </Card>
  );
}
