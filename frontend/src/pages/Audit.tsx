/**
 * /audit — governed by docs/security.md and docs/doctrine.md §8
 * ("audit everything").
 *
 * Read-only audit log (view_audit permission; the auditor role lives for
 * this page). Every entry records actor, action, subject, real client IP
 * (CF-Connecting-IP via Nginx — docs/security.md), and details. The UI never
 * offers edit/delete on audit rows.
 */
import { useEffect, useState } from "react";
import { api, type AuditEntry } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);

  useEffect(() => {
    api.audit.list().then(setEntries).catch(() => setEntries([]));
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Audit log</h1>
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Entries</CardTitle>
        </CardHeader>
        <CardContent>
          {entries.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No audit entries yet (or API not reachable). Filtering and
              export placeholder.
            </p>
          ) : (
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b text-muted-foreground">
                  <th className="py-2 pr-4 font-medium">When</th>
                  <th className="py-2 pr-4 font-medium">Actor</th>
                  <th className="py-2 pr-4 font-medium">Action</th>
                  <th className="py-2 pr-4 font-medium">Subject</th>
                  <th className="py-2 font-medium">IP</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => (
                  <tr key={entry.id} className="border-b last:border-0">
                    <td className="py-2 pr-4 text-xs text-muted-foreground">
                      {entry.created_at}
                    </td>
                    <td className="py-2 pr-4">{entry.actor}</td>
                    <td className="py-2 pr-4">
                      <code className="text-xs">{entry.action}</code>
                    </td>
                    <td className="py-2 pr-4">{entry.subject}</td>
                    <td className="py-2">
                      <code className="text-xs">{entry.ip}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
