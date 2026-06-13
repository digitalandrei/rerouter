import { useNavigate } from "react-router-dom";
import { SlidersHorizontal } from "lucide-react";
import { type Interface } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { classifyInterface, TYPE_VARIANT, fmtBps, fmtPps } from "@/lib/telemetry";
import { StatusBadge } from "@/components/status-badge";

interface InterfacesTabProps {
  deviceId: number;
  interfaces: Interface[];
  loading: boolean;
  ruleCountByIfaceId: Map<number, number>;
}

export function InterfacesTab({
  deviceId,
  interfaces,
  loading,
  ruleCountByIfaceId,
}: InterfacesTabProps) {
  const navigate = useNavigate();

  if (loading) {
    return <p className="px-6 pb-6 text-sm text-muted-foreground">Loading…</p>;
  }
  if (interfaces.length === 0) {
    return (
      <p className="px-6 pb-6 text-sm text-muted-foreground">
        No interfaces discovered yet. Use Refresh above.
      </p>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="pl-6">Name</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>Descr / Alias</TableHead>
          <TableHead>Speed</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Rx bps / pps</TableHead>
          <TableHead>Tx bps / pps</TableHead>
          <TableHead>Util %</TableHead>
          <TableHead className="pr-6">Rules</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {interfaces.map((iface) => {
          const ifType = classifyInterface(iface.if_name, iface.if_descr);
          const valid = iface.metrics && iface.metrics.valid_sample;
          const count = ruleCountByIfaceId.get(iface.id) ?? 0;
          return (
            <TableRow
              key={iface.id}
              className="cursor-pointer hover:bg-muted/50"
              onClick={() => navigate(`/devices/${deviceId}/interfaces/${iface.id}`)}
            >
              <TableCell className="pl-6 font-medium">{iface.if_name}</TableCell>
              <TableCell>
                <Badge variant={TYPE_VARIANT[ifType]}>{ifType}</Badge>
              </TableCell>
              <TableCell className="text-xs text-muted-foreground">
                {iface.if_alias ?? iface.if_descr ?? "—"}
              </TableCell>
              <TableCell className="text-xs">
                {iface.if_speed_bps !== null ? fmtBps(iface.if_speed_bps) : "—"}
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-1">
                  <StatusBadge value={iface.oper_status} />
                  {iface.admin_status !== iface.oper_status && (
                    <StatusBadge value={iface.admin_status} label={`adm:${iface.admin_status}`} />
                  )}
                </div>
              </TableCell>
              <TableCell className="text-xs">
                {valid ? (
                  <>
                    {fmtBps(iface.metrics!.rx_bps)}
                    <br />
                    {fmtPps(iface.metrics!.rx_pps)}
                  </>
                ) : (
                  "—"
                )}
              </TableCell>
              <TableCell className="text-xs">
                {valid ? (
                  <>
                    {fmtBps(iface.metrics!.tx_bps)}
                    <br />
                    {fmtPps(iface.metrics!.tx_pps)}
                  </>
                ) : (
                  "—"
                )}
              </TableCell>
              <TableCell className="text-xs">
                {valid ? (
                  <>
                    Rx {iface.metrics!.rx_util_percent.toFixed(1)}%
                    <br />
                    Tx {iface.metrics!.tx_util_percent.toFixed(1)}%
                  </>
                ) : (
                  "—"
                )}
              </TableCell>
              <TableCell className="pr-6">
                {count === 0 ? (
                  <span className="text-xs text-muted-foreground">—</span>
                ) : (
                  <Badge
                    variant="secondary"
                    className="inline-flex items-center gap-1"
                    title={`${count} detection rule${count === 1 ? "" : "s"} target this interface`}
                  >
                    <SlidersHorizontal className="size-3" />
                    {count}
                  </Badge>
                )}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}
