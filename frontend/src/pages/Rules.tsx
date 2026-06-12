/**
 * /rules — governed by docs/detection-engine.md and docs/doctrine.md §8.
 *
 * Detection-rule editor. Doctrine constraints this page must make visible:
 * automatic reroutes are OFF by default (global AND per-rule) and a rule may
 * only bind an allowlisted reroute template with a parameter schema — never
 * free text. Action history must be shown near each rule.
 */
import { useEffect, useState } from "react";
import { api, type DetectionRule } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function Rules() {
  const [rules, setRules] = useState<DetectionRule[]>([]);

  useEffect(() => {
    api.rules.list().then(setRules).catch(() => setRules([]));
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Detection rules</h1>
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Rules</CardTitle>
        </CardHeader>
        <CardContent>
          {rules.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No rules yet (or API not reachable). Rule editor placeholder —
              template binding is allowlist-only; automatic reroute is opt-in
              per rule and globally.
            </p>
          ) : (
            <ul className="divide-y">
              {rules.map((rule) => (
                <li
                  key={rule.id}
                  className="flex items-center gap-3 py-3 text-sm"
                >
                  <span className="font-medium">{rule.name}</span>
                  <span className="flex-1" />
                  <Badge variant={rule.enabled ? "default" : "outline"}>
                    {rule.enabled ? "enabled" : "disabled"}
                  </Badge>
                  <Badge
                    variant={
                      rule.automatic_reroute_enabled
                        ? "destructive"
                        : "secondary"
                    }
                  >
                    auto-reroute:{" "}
                    {rule.automatic_reroute_enabled ? "ON" : "off"}
                  </Badge>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
