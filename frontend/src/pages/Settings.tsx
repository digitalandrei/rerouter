/**
 * /settings — governed by docs/doctrine.md §8 (global safety switches),
 * docs/operations-runbook.md and docs/authentication.md (user management
 * lives behind manage_users; lock controls behind manage_locks).
 *
 * Hosts: the operating mode (observe = read-only/alert-only, the shipped
 * default; enforce flips are admin-only and audited), the global
 * automatic-reroute kill switch (default OFF), the global maintenance lock
 * (POST/DELETE /api/locks/global), cooldown display, alert settings, and
 * user/role administration. Enabling automation or clearing a lock is a
 * deliberate, audited act — destructive styling, no defaults that loosen
 * safety.
 */
import { useEffect, useState } from "react";
import { api, type SystemSettings } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function Settings() {
  const [settings, setSettings] = useState<SystemSettings | null>(null);

  useEffect(() => {
    api.settings.get().then(setSettings).catch(() => setSettings(null));
  }, []);

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Settings</h1>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Operating mode</CardTitle>
          <CardDescription>
            observe = safe read-only / alert-only: no reroute executes, manual
            or automatic; alerts show the actions that would have run. Flipping
            to enforce is admin-only and audited (doctrine §8, gate 0).
          </CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-3">
          <Badge
            variant={
              settings?.operating_mode === "enforce" ? "destructive" : "outline"
            }
          >
            {settings?.operating_mode === "enforce"
              ? "ENFORCE"
              : "observe (read-only / alert-only)"}
          </Badge>
          <span className="text-sm text-muted-foreground">
            Mode switch placeholder — PUT /api/settings (re-auth required).
          </span>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Automatic reroutes</CardTitle>
          <CardDescription>
            Off by default, globally and per-rule (doctrine §8); only effective
            in enforce mode. Enabling this is audited.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-3">
          <Badge
            variant={
              settings?.automatic_actions_enabled ? "destructive" : "outline"
            }
          >
            {settings?.automatic_actions_enabled ? "ENABLED" : "disabled"}
          </Badge>
          <span className="text-sm text-muted-foreground">
            Toggle UI placeholder — PUT /api/settings.
          </span>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Global maintenance lock</CardTitle>
          <CardDescription>
            While locked, no reroute actions run at all (manage_locks).
          </CardDescription>
        </CardHeader>
        <CardContent className="flex items-center gap-3">
          <Badge variant={settings?.global_lock ? "destructive" : "outline"}>
            {settings?.global_lock ? "LOCKED" : "clear"}
          </Badge>
          <Button
            variant="destructive"
            size="sm"
            onClick={() =>
              void api.locks.setGlobal("manual lock via settings page")
            }
          >
            Set lock
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void api.locks.clearGlobal()}
          >
            Clear lock
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Users & roles</CardTitle>
          <CardDescription>
            Placeholder — admin/operator/viewer/auditor role assignment and
            TOTP/recovery-code resets (manage_users).
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Not implemented yet.
        </CardContent>
      </Card>
    </div>
  );
}
