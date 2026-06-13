/**
 * /login — governed by docs/authentication.md and docs/doctrine.md §9.
 *
 * Two-step flow against the controller:
 *   1. POST /api/auth/login with email+password. A correct password ALWAYS
 *      yields a TOTP challenge (2FA is mandatory). On first login the
 *      response also carries enrollment material (otpauth URL + secret).
 *   2. POST /api/auth/totp with the 6-digit code -> session cookie issued.
 *
 * Throttling/lockout happen server-side (per email + real client IP via
 * CF-Connecting-IP); this page only surfaces the resulting errors verbatim.
 */
import { useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { QRCodeSVG } from "qrcode.react";
import { useAuth } from "@/lib/auth";
import { ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export default function Login() {
  const { stage, enrollment, login, submitTotp } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showQr, setShowQr] = useState(false);

  if (stage === "authenticated") {
    return <Navigate to="/dashboard" replace />;
  }

  async function handlePassword(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(email, password);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleTotp(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await submitTotp(code);
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Invalid code");
    } finally {
      setBusy(false);
    }
  }

  const inputClass =
    "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-md">
        {stage !== "totp" ? (
          <>
            <CardHeader>
              <CardTitle>Rerouter</CardTitle>
              <CardDescription>Sign in to the control plane.</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handlePassword} className="space-y-4">
                <label className="block space-y-1 text-sm font-medium">
                  Email
                  <input
                    type="email"
                    required
                    autoComplete="username"
                    className={inputClass}
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Password
                  <input
                    type="password"
                    required
                    autoComplete="current-password"
                    className={inputClass}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </label>
                {error && (
                  <p className="text-sm text-destructive" role="alert">
                    {error}
                  </p>
                )}
                <Button type="submit" className="w-full" disabled={busy}>
                  Continue
                </Button>
              </form>
            </CardContent>
          </>
        ) : (
          <>
            <CardHeader>
              <CardTitle>Two-factor authentication</CardTitle>
              <CardDescription>
                Enter the 6-digit code from your authenticator app, or a
                single-use recovery code.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {enrollment && (
                /* First-login enrollment. The QR is rendered client-side
                   (qrcode.react) so the otpauth secret never leaves the
                   browser; it stays hidden behind a toggle. The raw secret is
                   the manual fallback per docs/authentication.md. */
                <div className="rounded-md border bg-muted p-4 text-sm">
                  <p className="font-semibold">
                    First login — enroll your authenticator
                  </p>
                  <p className="mt-2 text-muted-foreground">
                    Scan the QR code with your authenticator app (Google
                    Authenticator, Authy, 1Password…), or enter the secret
                    manually.
                  </p>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="mt-3"
                    onClick={() => setShowQr((v) => !v)}
                  >
                    {showQr ? "Hide QR code" : "Show QR code"}
                  </Button>
                  {showQr && (
                    <div className="mt-3 flex justify-center rounded-md bg-white p-4">
                      <QRCodeSVG
                        value={enrollment.otpauth_url}
                        size={192}
                        marginSize={2}
                      />
                    </div>
                  )}
                  <p className="mt-3 text-muted-foreground">
                    Manual entry secret:
                  </p>
                  <code className="block break-all text-xs">
                    {enrollment.secret}
                  </code>
                  <p className="mt-2 text-muted-foreground">
                    Recovery codes are shown once after your first successful
                    code — store them offline.
                  </p>
                </div>
              )}
              <form onSubmit={handleTotp} className="space-y-4">
                <label className="block space-y-1 text-sm font-medium">
                  Code
                  <input
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    required
                    className={inputClass}
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                  />
                </label>
                {error && (
                  <p className="text-sm text-destructive" role="alert">
                    {error}
                  </p>
                )}
                <Button type="submit" className="w-full" disabled={busy}>
                  Verify
                </Button>
              </form>
            </CardContent>
          </>
        )}
      </Card>
    </div>
  );
}
