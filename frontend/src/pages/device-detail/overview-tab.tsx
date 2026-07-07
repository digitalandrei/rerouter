import type { ReactNode } from "react";
import { type Device } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ToneBadge } from "@/components/status-badge";

/** Uppercase-label / bold-value cell used in the info cards. */
function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-0.5">
      <dt className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </dt>
      <dd className="text-sm font-semibold break-words">{children}</dd>
    </div>
  );
}

export function OverviewTab({ device }: { device: Device }) {
  const sshMethodLabel =
    device.ssh_auth_method === "password"
      ? "password"
      : device.ssh_auth_method === "key"
        ? "SSH key"
        : "none";

  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Device Information</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-4">
            <Fact label="Name">{device.name}</Fact>
            <Fact label="Vendor">{device.vendor ?? "—"}</Fact>
            <Fact label="Model">{device.model ?? "—"}</Fact>
            <Fact label="OS Version">{device.os_version ?? "—"}</Fact>
            <Fact label="Sys Name">{device.sys_name ?? "—"}</Fact>
            <Fact label="Sys Uptime">{device.sys_uptime ?? "—"}</Fact>
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Connectivity</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-4">
            <Fact label="Hostname / IP">
              <code className="text-xs">{device.hostname}</code>
            </Fact>
            <Fact label="SNMP">
              {device.snmp_version} · port {device.snmp_port}
            </Fact>
            <Fact label="SSH">
              <span className="flex flex-wrap items-center gap-1.5">
                {device.ssh_configured ? (
                  <>
                    <span>
                      {device.ssh_username ?? "—"} · {sshMethodLabel}
                    </span>
                    <ToneBadge tone="good">configured</ToneBadge>
                  </>
                ) : (
                  <Badge variant="secondary">none</Badge>
                )}
              </span>
            </Fact>
            <Fact label="Poll Interval">{device.poll_interval_seconds} s</Fact>
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Status</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-4">
            <Fact label="Reachable">
              {device.reachable ? (
                <ToneBadge tone="good">reachable</ToneBadge>
              ) : (
                <ToneBadge tone="bad">unreachable</ToneBadge>
              )}
            </Fact>
            <Fact label="Interfaces">{device.interface_count}</Fact>
            <Fact label="Last Poll">
              {device.last_poll_at ? new Date(device.last_poll_at).toLocaleString() : "—"}
            </Fact>
            <Fact label="Last Error">
              {device.last_error ? (
                <span className="text-destructive">{device.last_error}</span>
              ) : (
                "—"
              )}
            </Fact>
          </dl>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Reachability (for mitigations)</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-4">
            <Fact label="SSH">
              <span className="flex flex-wrap items-center gap-1.5">
                <ToneBadge tone={device.ssh_recent ? "good" : "warn"}>
                  {device.ssh_recent ? "recently reachable" : "not recently confirmed"}
                </ToneBadge>
                <span className="text-xs font-normal text-muted-foreground">
                  {device.last_ssh_ok_at
                    ? new Date(device.last_ssh_ok_at).toLocaleString()
                    : "never"}
                </span>
              </span>
            </Fact>
            <Fact label="Telnet">
              <span className="flex flex-wrap items-center gap-1.5">
                <Badge variant="secondary" className="font-normal">
                  {device.telnet_reachable ? "open" : "closed"}
                </Badge>
                <span className="text-xs font-normal text-muted-foreground">
                  {device.last_telnet_ok_at
                    ? new Date(device.last_telnet_ok_at).toLocaleString()
                    : "never"}
                </span>
              </span>
            </Fact>
          </dl>
        </CardContent>
      </Card>
    </div>
  );
}
