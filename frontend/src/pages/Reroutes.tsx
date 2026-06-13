/**
 * /reroutes — governed by docs/reroute-engine.md, docs/state-recovery.md and
 * docs/doctrine.md §8.
 *
 * Reroute history with the two-phase state machine:
 * planned -> pending -> running -> verifying -> {succeeded, failed, uncertain}.
 * `uncertain` is the most important state: it locks the device and must be
 * impossible to miss. The detail drawer shows every command, its raw output,
 * and the verification read. Cancel / acknowledge-uncertain / rollback live in
 * the drawer ("sent" is never shown as success).
 */
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import {
  api,
  type Reroute,
  type RerouteDetail,
  type Lock,
} from "@/lib/api";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { PromptDialog } from "@/components/prompt-dialog";
import { StateBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ShieldAlert, Shuffle } from "lucide-react";

function RerouteDrawer({
  id,
  onClose,
  onChanged,
}: {
  id: number;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [detail, setDetail] = useState<RerouteDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const [ackOpen, setAckOpen] = useState(false);
  const [rollbackOpen, setRollbackOpen] = useState(false);

  const load = useCallback(() => {
    api.reroutes.get(id).then(setDetail).catch(() => setDetail(null));
  }, [id]);
  useEffect(() => {
    load();
  }, [load]);

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    try {
      await fn();
      load();
      onChanged();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "action failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            Mitigation #{id}
            {detail && <StateBadge state={detail.state} />}
          </DialogTitle>
        </DialogHeader>
        {!detail ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : (
          <div className="max-h-[70vh] space-y-4 overflow-y-auto">
            <div className="grid grid-cols-2 gap-2 text-sm">
              <div>
                <span className="text-muted-foreground">Template: </span>
                <code className="text-xs">{detail.template_name ?? "—"}</code>
              </div>
              <div>
                <span className="text-muted-foreground">Device: </span>
                {detail.device_name ?? "—"}
              </div>
              <div>
                <span className="text-muted-foreground">Trigger: </span>
                {detail.trigger_type}
              </div>
              <div>
                <span className="text-muted-foreground">By: </span>
                {detail.triggered_by ?? "—"}
              </div>
              <div className="col-span-2">
                <span className="text-muted-foreground">Verification: </span>
                {detail.verification_status ?? "—"}
              </div>
              {detail.reason && (
                <div className="col-span-2">
                  <span className="text-muted-foreground">Reason: </span>
                  {detail.reason}
                </div>
              )}
              {detail.failure_reason && (
                <div className="col-span-2 text-destructive">{detail.failure_reason}</div>
              )}
            </div>

            {detail.outputs.length > 0 && (
              <div className="space-y-2">
                <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Commands &amp; output
                </div>
                {detail.outputs.map((o, i) => (
                  <div key={i} className="rounded-md border border-border">
                    <div className="border-b border-border bg-muted/40 px-2 py-1 font-mono text-xs">
                      $ {o.request}
                      {o.status && o.status !== "ok" && (
                        <span className="ml-2 text-destructive">[{o.status}]</span>
                      )}
                    </div>
                    {o.response && (
                      <pre className="overflow-x-auto p-2 text-xs">{o.response}</pre>
                    )}
                  </div>
                ))}
              </div>
            )}

            {detail.verifications.length > 0 && (
              <div className="space-y-1 text-xs">
                <div className="font-medium uppercase tracking-wide text-muted-foreground">
                  Verification
                </div>
                {detail.verifications.map((v, i) => (
                  <div key={i}>
                    <Badge
                      variant={v.result === "pass" ? "default" : "destructive"}
                      className="mr-2"
                    >
                      {v.result}
                    </Badge>
                    <code>{v.expected}</code>
                  </div>
                ))}
              </div>
            )}

            <div className="flex flex-wrap gap-2 border-t border-border pt-3">
              {(detail.state === "planned" || detail.state === "pending") && (
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() => void act(() => api.reroutes.cancel(detail.id))}
                >
                  Cancel
                </Button>
              )}
              {detail.state === "uncertain" && (
                <Button
                  size="sm"
                  variant="destructive"
                  disabled={busy}
                  onClick={() => setAckOpen(true)}
                >
                  Acknowledge uncertain (clears device lock)
                </Button>
              )}
              {detail.state === "succeeded" && (
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy}
                  onClick={() => setRollbackOpen(true)}
                >
                  Roll back
                </Button>
              )}
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>

    {detail && (
      <PromptDialog
        open={ackOpen}
        onOpenChange={setAckOpen}
        title="Acknowledge uncertain mitigation"
        description="This resolves the action and clears the device lock so reroutes can resume."
        label="Acknowledgement note (what did you verify on the router?)"
        multiline
        submitLabel="Acknowledge"
        onSubmit={async (note) => {
          setAckOpen(false);
          await act(() => api.reroutes.acknowledgeUncertain(detail.id, note));
        }}
      />
    )}
    {detail && (
      <ConfirmDialog
        open={rollbackOpen}
        onOpenChange={setRollbackOpen}
        title="Roll back this action"
        description="Runs the template's rollback against the same router and parameters now."
        confirmLabel="Roll back"
        onConfirm={async () => {
          setRollbackOpen(false);
          await act(() => api.reroutes.rollback(detail.id));
        }}
      />
    )}
    </>
  );
}

export default function Reroutes() {
  const [reroutes, setReroutes] = useState<Reroute[]>([]);
  const [locks, setLocks] = useState<Lock[]>([]);
  const [openId, setOpenId] = useState<number | null>(null);

  const load = useCallback(() => {
    api.reroutes.list().then(setReroutes).catch(() => setReroutes([]));
    api.locks.list().then(setLocks).catch(() => setLocks([]));
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  const safetyLocks = locks.filter((l) => l.kind !== "manual" || l.scope === "device");

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Mitigations</h1>
        <Button asChild variant="outline">
          <Link to="/mitigations/manual">
            <Shuffle className="size-4" />
            Manual mitigation
          </Link>
        </Button>
      </div>

      {safetyLocks.length > 0 && (
        <Card className="border-destructive/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base text-destructive">
              <ShieldAlert className="size-4" />
              Safety locks active
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1 text-sm">
            {safetyLocks.map((l) => (
              <div key={l.id}>
                <Badge variant="destructive" className="mr-2">
                  {l.scope}
                  {l.scope_ref ? ` #${l.scope_ref}` : ""}
                </Badge>
                <span className="text-muted-foreground">
                  {l.kind} — {l.reason ?? ""}
                </span>
              </div>
            ))}
            <p className="pt-1 text-xs text-muted-foreground">
              A locked device blocks mitigations until the related uncertain action is acknowledged.
            </p>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="px-0 py-2">
          {reroutes.length === 0 ? (
            <p className="px-6 py-4 text-sm text-muted-foreground">
              No mitigation actions yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-6">#</TableHead>
                  <TableHead>Template</TableHead>
                  <TableHead>Device</TableHead>
                  <TableHead>Trigger</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>When</TableHead>
                  <TableHead className="pr-6 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reroutes.map((r) => (
                  <TableRow key={r.id} className="hover:bg-muted/50">
                    <TableCell className="pl-6 font-medium">{r.id}</TableCell>
                    <TableCell>
                      <code className="text-xs">{r.template_name ?? "—"}</code>
                    </TableCell>
                    <TableCell>{r.device_name ?? "—"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{r.trigger_type}</TableCell>
                    <TableCell>
                      <StateBadge state={r.state} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(r.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="pr-6 text-right">
                      <Button size="sm" variant="ghost" onClick={() => setOpenId(r.id)}>
                        View
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {openId !== null && (
        <RerouteDrawer id={openId} onClose={() => setOpenId(null)} onChanged={load} />
      )}
    </div>
  );
}
