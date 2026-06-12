/**
 * /dashboard — governed by docs/doctrine.md §5.3 (UI principles) and
 * docs/operations-runbook.md.
 *
 * Must show, prominently and without drill-down: system status, telemetry
 * freshness (live / cached / degraded / unknown), active reroutes, any
 * unresolved `uncertain` actions, and the global lock state.
 */
import { useEffect, useState } from "react";
import { api, type SystemStatus } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function Dashboard() {
  const [status, setStatus] = useState<SystemStatus | null>(null);

  useEffect(() => {
    api.status().then(setStatus).catch(() => setStatus(null));
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader>
            <CardDescription>Telemetry</CardDescription>
            <CardTitle className="text-lg">
              <Badge
                variant={
                  status?.telemetry === "live" ? "default" : "destructive"
                }
              >
                {status?.telemetry ?? "unknown"}
              </Badge>
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Active reroutes</CardDescription>
            <CardTitle className="text-lg">
              {status?.active_reroutes ?? "—"}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Unresolved uncertain</CardDescription>
            <CardTitle className="text-lg">
              {status?.unresolved_uncertain ?? "—"}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader>
            <CardDescription>Global lock</CardDescription>
            <CardTitle className="text-lg">
              <Badge variant={status?.global_lock ? "destructive" : "outline"}>
                {status?.global_lock ? "LOCKED" : "clear"}
              </Badge>
            </CardTitle>
          </CardHeader>
        </Card>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Recent activity</CardTitle>
          <CardDescription>
            Placeholder — recent detections, reroutes, and alerts feed.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Not implemented yet.
        </CardContent>
      </Card>
    </div>
  );
}
