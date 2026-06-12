/**
 * /reroutes — governed by docs/reroute-engine.md, docs/state-recovery.md and
 * docs/doctrine.md §8.
 *
 * Lists reroute actions with their two-phase state machine state:
 * planned -> pending -> running -> verifying -> {succeeded, failed, uncertain}.
 * `uncertain` is the most important state on this page: it locks the asset
 * and must be impossible to miss. Cancel and acknowledge-uncertain actions
 * live here (acknowledge requires the acknowledge_uncertain_reroute
 * permission and a note; "sent" is never displayed as success).
 */
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, type Reroute, type RerouteState } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

function stateVariant(
  state: RerouteState,
): "default" | "secondary" | "destructive" | "outline" {
  switch (state) {
    case "succeeded":
      return "default";
    case "failed":
    case "uncertain":
      return "destructive";
    case "planned":
    case "pending":
      return "outline";
    default:
      return "secondary";
  }
}

export default function Reroutes() {
  const navigate = useNavigate();
  const [reroutes, setReroutes] = useState<Reroute[]>([]);

  useEffect(() => {
    api.reroutes.list().then(setReroutes).catch(() => setReroutes([]));
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Reroutes</h1>
        <Button
          variant="destructive"
          onClick={() => navigate("/reroutes/manual")}
        >
          Manual reroute
        </Button>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Actions</CardTitle>
        </CardHeader>
        <CardContent>
          {reroutes.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No reroute actions yet (or API not reachable).
            </p>
          ) : (
            <ul className="divide-y">
              {reroutes.map((reroute) => (
                <li
                  key={reroute.id}
                  className="flex items-center gap-3 py-3 text-sm"
                >
                  <span className="font-medium">#{reroute.id}</span>
                  <code className="text-xs">{reroute.template}</code>
                  <span className="flex-1" />
                  <Badge variant={stateVariant(reroute.state)}>
                    {reroute.state}
                  </Badge>
                  {(reroute.state === "planned" ||
                    reroute.state === "pending") && (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => void api.reroutes.cancel(reroute.id)}
                    >
                      Cancel
                    </Button>
                  )}
                  {reroute.state === "uncertain" && (
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() =>
                        void api.reroutes.acknowledgeUncertain(
                          reroute.id,
                          "acknowledged via UI (note dialog TODO)",
                        )
                      }
                    >
                      Acknowledge uncertain
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
