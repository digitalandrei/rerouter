/**
 * /devices — SNMP device management.
 *
 * Lists enrolled devices with reachability badges. Supports adding a new
 * device (name, hostname, SNMP version, community, port, poll interval)
 * and per-row Test (POST /devices/{id}/test) and Discover
 * (POST /devices/{id}/discover) actions.
 */
import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api, type Device, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

interface AddDeviceForm {
  name: string;
  hostname: string;
  snmp_version: string;
  community: string;
  snmp_port: string;
  poll_interval_seconds: string;
  // SSH access (password XOR key). "none" | "password" | "key" — "none" skips
  // SSH enrollment. Kept as a plain string so the shared setField stays simple.
  ssh_auth_method: string;
  ssh_username: string;
  ssh_port: string;
  ssh_password: string;
  ssh_private_key: string;
  ssh_key_passphrase: string;
}

const DEFAULT_FORM: AddDeviceForm = {
  name: "",
  hostname: "",
  snmp_version: "v2c",
  community: "public",
  snmp_port: "161",
  poll_interval_seconds: "60",
  ssh_auth_method: "none",
  ssh_username: "",
  ssh_port: "22",
  ssh_password: "",
  ssh_private_key: "",
  ssh_key_passphrase: "",
};

function reachabilityVariant(
  ok: boolean,
): "default" | "secondary" | "destructive" | "outline" {
  return ok ? "default" : "destructive";
}

export default function Devices() {
  const { hasPermission } = useAuth();
  const canEnroll = hasPermission("manage_devices");
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState<AddDeviceForm>(DEFAULT_FORM);
  const [addError, setAddError] = useState<string | null>(null);
  const [addBusy, setAddBusy] = useState(false);
  // Per-device test/discover feedback: deviceId -> message
  const [feedback, setFeedback] = useState<Record<number, string>>({});

  function loadDevices() {
    setLoading(true);
    api.devices
      .list()
      .then(setDevices)
      .catch(() => setDevices([]))
      .finally(() => setLoading(false));
  }

  useEffect(loadDevices, []);

  function setField(field: keyof AddDeviceForm, value: string) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  async function handleAdd(e: FormEvent) {
    e.preventDefault();
    setAddError(null);
    setAddBusy(true);
    try {
      const payload: Parameters<typeof api.devices.create>[0] = {
        name: form.name.trim(),
        hostname: form.hostname.trim(),
        snmp_version: form.snmp_version,
        snmp_port: parseInt(form.snmp_port, 10),
        community: form.community.trim(),
        poll_interval_seconds: parseInt(form.poll_interval_seconds, 10),
      };
      if (form.ssh_auth_method !== "none") {
        payload.ssh_auth_method = form.ssh_auth_method as "password" | "key";
        payload.ssh_username = form.ssh_username.trim();
        payload.ssh_port = parseInt(form.ssh_port, 10);
        if (form.ssh_auth_method === "password") {
          payload.ssh_password = form.ssh_password;
        } else {
          payload.ssh_private_key = form.ssh_private_key;
          if (form.ssh_key_passphrase) {
            payload.ssh_key_passphrase = form.ssh_key_passphrase;
          }
        }
      }
      await api.devices.create(payload);
      setForm(DEFAULT_FORM);
      setShowAdd(false);
      loadDevices();
    } catch (err) {
      setAddError(err instanceof ApiError ? err.message : "Failed to add device");
    } finally {
      setAddBusy(false);
    }
  }

  async function handleTest(device: Device) {
    setFeedback((f) => ({ ...f, [device.id]: "Testing…" }));
    try {
      const result = await api.devices.test(device.id);
      if (result.ok) {
        const info = [result.vendor, result.model, result.os_version]
          .filter(Boolean)
          .join(" / ");
        setFeedback((f) => ({
          ...f,
          [device.id]: info ? `OK: ${info}` : "OK",
        }));
      } else {
        setFeedback((f) => ({
          ...f,
          [device.id]: `Failed: ${result.error ?? "unknown error"}`,
        }));
      }
    } catch (err) {
      setFeedback((f) => ({
        ...f,
        [device.id]: err instanceof ApiError ? err.message : "Test failed",
      }));
    }
  }

  async function handleDiscover(device: Device) {
    setFeedback((f) => ({ ...f, [device.id]: "Discovering…" }));
    try {
      const result = await api.devices.discover(device.id);
      setFeedback((f) => ({
        ...f,
        [device.id]: `Discovered ${result.discovered} interfaces`,
      }));
      loadDevices();
    } catch (err) {
      setFeedback((f) => ({
        ...f,
        [device.id]: err instanceof ApiError ? err.message : "Discover failed",
      }));
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Devices</h1>
        {canEnroll ? (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowAdd((v) => !v)}
          >
            {showAdd ? "Cancel" : "Add device"}
          </Button>
        ) : (
          <p className="text-sm text-muted-foreground">
            Device enrollment is restricted to super admins.
          </p>
        )}
      </div>

      {showAdd && canEnroll && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Add SNMP device</CardTitle>
            <CardDescription>
              Enroll a new router or switch for SNMP polling.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleAdd} className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block space-y-1 text-sm font-medium">
                  Name
                  <input
                    required
                    className={inputClass}
                    value={form.name}
                    onChange={(e) => setField("name", e.target.value)}
                    placeholder="core-router-01"
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Hostname / IP
                  <input
                    required
                    className={inputClass}
                    value={form.hostname}
                    onChange={(e) => setField("hostname", e.target.value)}
                    placeholder="192.168.1.1"
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  SNMP version
                  <select
                    className={inputClass}
                    value={form.snmp_version}
                    onChange={(e) => setField("snmp_version", e.target.value)}
                  >
                    <option value="v2c">v2c</option>
                    <option value="v1">v1</option>
                    <option value="v3">v3</option>
                  </select>
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Community string
                  <input
                    required
                    className={inputClass}
                    value={form.community}
                    onChange={(e) => setField("community", e.target.value)}
                    placeholder="public"
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  SNMP port
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    required
                    className={inputClass}
                    value={form.snmp_port}
                    onChange={(e) => setField("snmp_port", e.target.value)}
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Poll interval (seconds)
                  <input
                    type="number"
                    min={10}
                    required
                    className={inputClass}
                    value={form.poll_interval_seconds}
                    onChange={(e) =>
                      setField("poll_interval_seconds", e.target.value)
                    }
                  />
                </label>
              </div>

              {/* SSH access — captured at onboarding for future CLI reroute
                  actions; not used in observe mode. Password XOR key. */}
              <div className="space-y-4 rounded-md border border-border p-4">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium">SSH access</p>
                  <span className="text-xs text-muted-foreground">
                    stored encrypted · unused in observe mode
                  </span>
                </div>
                <div className="grid gap-4 sm:grid-cols-2">
                  <label className="block space-y-1 text-sm font-medium">
                    Auth method
                    <select
                      className={inputClass}
                      value={form.ssh_auth_method}
                      onChange={(e) => setField("ssh_auth_method", e.target.value)}
                    >
                      <option value="none">None (SNMP only)</option>
                      <option value="password">Password</option>
                      <option value="key">SSH key</option>
                    </select>
                  </label>
                  {form.ssh_auth_method !== "none" && (
                    <>
                      <label className="block space-y-1 text-sm font-medium">
                        SSH username
                        <input
                          required
                          className={inputClass}
                          value={form.ssh_username}
                          onChange={(e) => setField("ssh_username", e.target.value)}
                          placeholder="admin"
                          autoComplete="off"
                        />
                      </label>
                      <label className="block space-y-1 text-sm font-medium">
                        SSH port
                        <input
                          type="number"
                          min={1}
                          max={65535}
                          required
                          className={inputClass}
                          value={form.ssh_port}
                          onChange={(e) => setField("ssh_port", e.target.value)}
                        />
                      </label>
                    </>
                  )}
                </div>
                {form.ssh_auth_method === "password" && (
                  <label className="block space-y-1 text-sm font-medium">
                    SSH password
                    <input
                      type="password"
                      required
                      className={inputClass}
                      value={form.ssh_password}
                      onChange={(e) => setField("ssh_password", e.target.value)}
                      autoComplete="new-password"
                    />
                  </label>
                )}
                {form.ssh_auth_method === "key" && (
                  <div className="space-y-4">
                    <label className="block space-y-1 text-sm font-medium">
                      SSH private key
                      <textarea
                        required
                        rows={6}
                        className={`${inputClass} font-mono text-xs`}
                        value={form.ssh_private_key}
                        onChange={(e) =>
                          setField("ssh_private_key", e.target.value)
                        }
                        placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                      />
                    </label>
                    <label className="block space-y-1 text-sm font-medium">
                      Key passphrase (optional)
                      <input
                        type="password"
                        className={inputClass}
                        value={form.ssh_key_passphrase}
                        onChange={(e) =>
                          setField("ssh_key_passphrase", e.target.value)
                        }
                        autoComplete="new-password"
                      />
                    </label>
                  </div>
                )}
              </div>

              {addError && (
                <p className="text-sm text-destructive" role="alert">
                  {addError}
                </p>
              )}
              <Button type="submit" disabled={addBusy}>
                {addBusy ? "Adding…" : "Add device"}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Enrolled devices</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : devices.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No devices enrolled yet. Use "Add device" to enroll your first
              SNMP-polled router.
            </p>
          ) : (
            <div className="divide-y">
              {devices.map((device) => (
                <div key={device.id} className="py-4">
                  <div className="flex flex-wrap items-center gap-3">
                    <Link
                      to={`/devices/${device.id}`}
                      className="font-medium underline-offset-4 hover:underline"
                    >
                      {device.name}
                    </Link>
                    <code className="text-xs text-muted-foreground">
                      {device.hostname}
                    </code>
                    <Badge variant={reachabilityVariant(device.reachable)}>
                      {device.reachable ? "reachable" : "unreachable"}
                    </Badge>
                    <Badge variant="secondary">{device.snmp_version}</Badge>
                    {device.vendor && (
                      <span className="text-xs text-muted-foreground">
                        {device.vendor}
                        {device.model ? ` ${device.model}` : ""}
                      </span>
                    )}
                    <span className="text-xs text-muted-foreground">
                      {device.interface_count} interfaces
                    </span>
                    <span className="flex-1" />
                    {canEnroll && (
                      <>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => void handleTest(device)}
                        >
                          Test
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => void handleDiscover(device)}
                        >
                          Discover
                        </Button>
                      </>
                    )}
                  </div>
                  {feedback[device.id] && (
                    <p className="mt-1 text-xs text-muted-foreground">
                      {feedback[device.id]}
                    </p>
                  )}
                  {device.last_error && (
                    <p className="mt-1 text-xs text-destructive">
                      Last error: {device.last_error}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
