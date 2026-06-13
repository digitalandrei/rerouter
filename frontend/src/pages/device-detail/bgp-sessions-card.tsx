import { useCallback, useEffect, useState } from "react";
import { Network } from "lucide-react";
import { api, type BgpPeer } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { StatusBadge } from "@/components/status-badge";
import { PromptDialog } from "@/components/prompt-dialog";

function adminLabel(s: string | null) {
  return s === "stop" ? "shutdown" : s === "start" ? "up" : "?";
}

/** Discovered BGP sessions (SNMP). Operators identify the scrubber neighbor here;
 *  rule actions later toggle it (shutdown / no shutdown). Reloads on refreshKey. */
export function BgpSessionsCard({
  deviceId,
  canManage,
  refreshKey,
}: {
  deviceId: number;
  canManage: boolean;
  refreshKey: number;
}) {
  const [peers, setPeers] = useState<BgpPeer[] | null>(null);
  const [labelPeer, setLabelPeer] = useState<BgpPeer | null>(null);

  const load = useCallback(() => {
    api.devices
      .bgpPeers(deviceId)
      .then(setPeers)
      .catch(() => setPeers([]));
  }, [deviceId]);
  useEffect(() => {
    load();
  }, [load, refreshKey]);

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Network className="size-4 text-muted-foreground" />
            BGP sessions
            <Badge variant="outline" className="ml-1 font-normal text-muted-foreground">
              SNMP
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {peers === null ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : peers.length === 0 ? (
            <p className="text-sm text-muted-foreground">No BGP sessions discovered yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Neighbor</TableHead>
                  <TableHead>Remote AS</TableHead>
                  <TableHead>Session</TableHead>
                  <TableHead>Admin</TableHead>
                  <TableHead>Label</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {peers.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell className="font-mono text-xs">{p.peer_remote_addr}</TableCell>
                    <TableCell>{p.peer_remote_as ?? "—"}</TableCell>
                    <TableCell>
                      <StatusBadge value={p.peer_state} />
                    </TableCell>
                    <TableCell>
                      <StatusBadge
                        value={adminLabel(p.peer_admin_status)}
                        label={adminLabel(p.peer_admin_status)}
                      />
                    </TableCell>
                    <TableCell>
                      {canManage ? (
                        <button
                          type="button"
                          onClick={() => setLabelPeer(p)}
                          className="text-left text-primary underline-offset-4 hover:underline"
                        >
                          {p.label ?? "set label"}
                        </button>
                      ) : (
                        (p.label ?? "—")
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {labelPeer && (
        <PromptDialog
          open={labelPeer !== null}
          onOpenChange={(v) => !v && setLabelPeer(null)}
          title="Neighbor label"
          label={`Label for ${labelPeer.peer_remote_addr}`}
          defaultValue={labelPeer.label ?? ""}
          placeholder="e.g. Scrubber-A GRE"
          onSubmit={async (value) => {
            const id = labelPeer.id;
            setLabelPeer(null);
            await api.devices.updateBgpPeer(deviceId, id, value.trim() || null).catch(() => {});
            load();
          }}
        />
      )}
    </>
  );
}
