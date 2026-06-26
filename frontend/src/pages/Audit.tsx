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
import { humanizeToken } from "@/lib/labels";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

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
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Subject</TableHead>
                  <TableHead>IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((entry) => (
                  <TableRow key={entry.id}>
                    <TableCell className="text-xs text-muted-foreground">
                      {entry.created_at}
                    </TableCell>
                    <TableCell>{entry.actor}</TableCell>
                    <TableCell className="text-sm">
                      {humanizeToken(entry.action)}
                    </TableCell>
                    <TableCell>{entry.subject}</TableCell>
                    <TableCell>
                      <code className="text-xs">{entry.ip}</code>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
