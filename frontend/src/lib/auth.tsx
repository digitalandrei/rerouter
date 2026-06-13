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
  | "anonymous" // no session; show password step
  | "totp" // password accepted; TOTP code (or enrollment) required
  | "authenticated";

export interface AuthState {
  stage: AuthStage;
  user: SessionUser | null;
  /** Present during the `totp` stage on first login only. */
  enrollment: LoginResponse["totp_enrollment"] | null;
  login: (email: string, password: string) => Promise<void>;
  submitTotp: (code: string) => Promise<void>;
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

  // Probe for an existing session on mount via GET /api/auth/me.
  // A 200 means the cookie is valid and returns the SessionUser.
  // A 401 means no session — go to anonymous/login.
  useEffect(() => {
    let cancelled = false;
    api.auth
      .me()
      .then((sessionUser) => {
        if (!cancelled) {
          setUser(sessionUser);
          setStage("authenticated");
        }
      })
      .catch(() => {
        if (!cancelled) setStage("anonymous");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const res = await api.auth.login(email, password);
    setEnrollment(res.totp_enrollment ?? null);
    setStage("totp");
  }, []);

  const submitTotp = useCallback(async (code: string) => {
    const res = await api.auth.totp(code);
    setUser(res.user);
    setEnrollment(null);
    setStage("authenticated");
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.auth.logout();
    } catch (err) {
      // Even if the server call fails, drop local state; the redirect to
      // /login keeps no operational data on screen.
      if (!(err instanceof ApiError)) throw err;
    } finally {
      setUser(null);
      setEnrollment(null);
      setStage("anonymous");
    }
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
      login,
      submitTotp,
      logout,
      hasPermission,
    }),
    [stage, user, enrollment, login, submitTotp, logout, hasPermission],
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
