/**
 * Auth context for the SPA.
 *
 * Governed by docs/authentication.md and docs/doctrine.md §9:
 * - login is two-step: password -> mandatory TOTP challenge -> session cookie
 *   (the cookie is HttpOnly and owned by the controller; the SPA never sees a
 *   token, it only tracks "who am I" state);
 * - first login returns TOTP enrollment material (otpauth URL + secret) which
 *   the Login page must display before the first code is accepted.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api, ApiError, type LoginResponse, type SessionUser } from "./api";

export type AuthStage =
  | "loading" // initial "do I have a session?" probe
  | "unavailable" // initial probe failed without proving the session absent
  | "reconnecting" // a known authenticated session is being revalidated
  | "anonymous" // no session; show password step
  | "totp" // password accepted; TOTP code (or enrollment) required
  | "recovery" // first enrollment complete; recovery codes must be acknowledged
  | "authenticated";

export interface AuthState {
  stage: AuthStage;
  user: SessionUser | null;
  /** Present during the `totp` stage on first login only. */
  enrollment: LoginResponse["totp_enrollment"] | null;
  recoveryCodes: string[];
  authError: string | null;
  retrySession: () => void;
  login: (
    email: string,
    password: string,
    remember?: boolean,
    enrollmentCode?: string,
  ) => Promise<void>;
  submitTotp: (code: string) => Promise<"recovery" | "authenticated">;
  finishRecoveryCodes: () => void;
  logout: () => Promise<void>;
  /** Fresh password+TOTP check before high-safety reroutes. */
  hasPermission: (permission: string) => boolean;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [stage, setStage] = useState<AuthStage>("loading");
  const [user, setUser] = useState<SessionUser | null>(null);
  const [enrollment, setEnrollment] =
    useState<LoginResponse["totp_enrollment"] | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [authError, setAuthError] = useState<string | null>(null);
  const [probeVersion, setProbeVersion] = useState(0);

  // Probe for an existing session on mount via GET /api/auth/me.
  // A 200 means the cookie is valid and returns the SessionUser.
  // A 401 means no session — go to anonymous/login.
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const probe = async (attempt = 0) => {
      if (user) setStage("reconnecting");
      try {
        const sessionUser = await api.auth.me();
        if (!cancelled) {
          setUser(sessionUser);
          setAuthError(null);
          setStage("authenticated");
        }
      } catch (error) {
        if (cancelled) return;
        if (error instanceof ApiError && error.status === 401) {
          setUser(null);
          setAuthError(null);
          setStage("anonymous");
          return;
        }
        if (attempt < 2) {
          timer = setTimeout(() => void probe(attempt + 1), 500 * 2 ** attempt);
          return;
        }
        setAuthError("The controller is unavailable. Your session has not been signed out.");
        setStage(user ? "reconnecting" : "unavailable");
      }
    };

    void probe();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [probeVersion]); // A manual retry starts a fresh, bounded probe sequence.

  const retrySession = useCallback(() => setProbeVersion((value) => value + 1), []);

  const login = useCallback(
    async (
      email: string,
      password: string,
      remember = false,
      enrollmentCode?: string,
    ) => {
      const res = await api.auth.login(
        email,
        password,
        remember,
        enrollmentCode,
      );
      setEnrollment(res.totp_enrollment ?? null);
      setStage("totp");
    },
    [],
  );

  const submitTotp = useCallback(async (code: string) => {
    const res = await api.auth.totp(code);
    setUser(res.user);
    setEnrollment(null);
    const codes = res.recovery_codes ?? [];
    setRecoveryCodes(codes);
    const next = codes.length > 0 ? "recovery" : "authenticated";
    setStage(next);
    return next;
  }, []);

  const finishRecoveryCodes = useCallback(() => {
    setRecoveryCodes([]);
    setStage("authenticated");
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.auth.logout();
    } catch (err) {
      // A failed mutation does not prove revocation. Keep the authenticated
      // shell and let the caller offer a deliberate retry.
      if (!(err instanceof ApiError && err.status === 401)) throw err;
    }
    setUser(null);
    setEnrollment(null);
    setRecoveryCodes([]);
    setStage("anonymous");
  }, []);

  const hasPermission = useCallback(
    (permission: string) => user?.permissions.includes(permission) ?? false,
    [user],
  );

  const value = useMemo<AuthState>(
    () => ({
      stage,
      user,
      enrollment,
      recoveryCodes,
      authError,
      retrySession,
      login,
      submitTotp,
      finishRecoveryCodes,
      logout,
      hasPermission,
    }),
    [
      stage,
      user,
      enrollment,
      recoveryCodes,
      authError,
      retrySession,
      login,
      submitTotp,
      finishRecoveryCodes,
      logout,
      hasPermission,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used inside <AuthProvider>");
  }
  return ctx;
}
