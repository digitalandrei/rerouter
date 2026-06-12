/**
 * /reroutes/manual — governed by docs/reroute-engine.md and
 * docs/doctrine.md §8 (safety model) + §9 (re-auth requirement).
 *
 * Doctrine, non-negotiable, enforced server-side and mirrored here:
 *  1. Reroutes only via ALLOWLISTED templates with parameter schemas — no
 *     free-text command box, ever.
 *  2. The EXACT reroute preview (template, asset, prefix, provider, method,
 *     resolved parameters) is rendered before submission; dangerous details
 *     are never hidden.
 *  3. High-safety templates require: fresh re-auth (password + TOTP via
 *     POST /api/auth/reauth), a TYPED confirmation phrase, and a mandatory
 *     reason — all validated again by the controller.
 *  4. Submission yields a `planned` action; the two-phase state machine and
 *     verification decide the outcome. "Sent" is never shown as success.
 */
import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

const CONFIRMATION_PHRASE = "REROUTE";

export default function ManualReroute() {
  const { reauth } = useAuth();
  const navigate = useNavigate();

  // Placeholder selection state — real implementation loads assets,
  // providers and the allowlisted template catalog (with parameter schemas)
  // from the API and renders schema-driven fields. No free-text commands.
  const [assetId] = useState<number | null>(null);
  const [providerId] = useState<number | null>(null);
  const [template] = useState<string>("");
  const [parameters] = useState<Record<string, unknown>>({});

  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [reauthPassword, setReauthPassword] = useState("");
  const [reauthCode, setReauthCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    if (confirmation !== CONFIRMATION_PHRASE) {
      setError(`Type ${CONFIRMATION_PHRASE} exactly to confirm.`);
      return;
    }
    if (reason.trim().length === 0) {
      setError("A reason is required; it is audited.");
      return;
    }
    if (assetId === null || providerId === null || template === "") {
      setError("Select an asset, provider, and template first.");
      return;
    }

    setBusy(true);
    try {
      // Fresh re-auth immediately before the high-safety action (§9). The
      // controller independently checks re-auth freshness; this call is the
      // UX half of that contract.
      await reauth(reauthPassword, reauthCode);
      await api.reroutes.manual({
        asset_id: assetId,
        provider_id: providerId,
        template,
        parameters,
        reason: reason.trim(),
        confirmation,
      });
      navigate("/reroutes");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Reroute rejected");
    } finally {
      setBusy(false);
    }
  }

  const inputClass =
    "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

  return (
    <div className="max-w-2xl space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Manual reroute</h1>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">1. Select action</CardTitle>
          <CardDescription>
            Placeholder — asset, provider, and allowlisted template pickers
            with schema-driven parameter fields. Free-text commands are
            forbidden by doctrine.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Template catalog not wired yet.
        </CardContent>
      </Card>

      <Card className="border-destructive">
        <CardHeader>
          <CardTitle className="text-lg">2. Exact reroute preview</CardTitle>
          <CardDescription>
            The precise action the controller will execute. Never hidden,
            never summarized.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-[10rem_1fr] gap-y-2 text-sm">
            <dt className="font-medium">Template</dt>
            <dd>
              <code>{template || "—"}</code>
            </dd>
            <dt className="font-medium">Asset / prefix</dt>
            <dd>{assetId ?? "—"}</dd>
            <dt className="font-medium">Provider / method</dt>
            <dd>{providerId ?? "—"}</dd>
            <dt className="font-medium">Parameters</dt>
            <dd>
              <pre className="rounded bg-muted p-2 text-xs">
                {JSON.stringify(parameters, null, 2)}
              </pre>
            </dd>
            <dt className="font-medium">Safety level</dt>
            <dd>
              <Badge variant="destructive">high (placeholder)</Badge>
            </dd>
            <dt className="font-medium">Rollback</dt>
            <dd className="text-muted-foreground">
              Rollback template shown here once a template is selected.
            </dd>
          </dl>
        </CardContent>
      </Card>

      <form onSubmit={handleSubmit}>
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">3. Confirm and re-auth</CardTitle>
            <CardDescription>
              High-safety reroutes require a typed confirmation, a reason, and
              fresh password + TOTP re-authentication.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <label className="block space-y-1 text-sm font-medium">
              Reason (audited, required)
              <textarea
                required
                className={inputClass}
                rows={2}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
              />
            </label>
            <label className="block space-y-1 text-sm font-medium">
              Type <code>{CONFIRMATION_PHRASE}</code> to confirm
              <input
                required
                className={inputClass}
                value={confirmation}
                onChange={(e) => setConfirmation(e.target.value)}
              />
            </label>
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block space-y-1 text-sm font-medium">
                Password
                <input
                  type="password"
                  required
                  autoComplete="current-password"
                  className={inputClass}
                  value={reauthPassword}
                  onChange={(e) => setReauthPassword(e.target.value)}
                />
              </label>
              <label className="block space-y-1 text-sm font-medium">
                TOTP code
                <input
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  required
                  className={inputClass}
                  value={reauthCode}
                  onChange={(e) => setReauthCode(e.target.value)}
                />
              </label>
            </div>
            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}
          </CardContent>
          <CardFooter className="gap-2">
            <Button type="submit" variant="destructive" disabled={busy}>
              Plan reroute
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={() => navigate("/reroutes")}
            >
              Cancel
            </Button>
          </CardFooter>
        </Card>
      </form>
    </div>
  );
}
