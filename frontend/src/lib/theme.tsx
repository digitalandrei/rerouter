import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

// Light / dark / system theme. The palettes live in styles/theme.css (`:root`
// = light, `.dark` = dark); this just toggles the `dark` class on <html> and
// persists the choice. Default is "system" (honour the OS), so the app ships
// with both light and dark working out of the box. index.html applies the
// stored choice before paint to avoid a flash.

export type Theme = "light" | "dark" | "system";
const STORAGE_KEY = "rerouter-theme";

type ThemeCtx = { theme: Theme; setTheme: (t: Theme) => void };
const ThemeContext = createContext<ThemeCtx>({ theme: "system", setTheme: () => {} });

function prefersDark(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function applyTheme(theme: Theme) {
  const dark = theme === "dark" || (theme === "system" && prefersDark());
  document.documentElement.classList.toggle("dark", dark);
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(
    () => (localStorage.getItem(STORAGE_KEY) as Theme | null) ?? "system",
  );

  useEffect(() => {
    applyTheme(theme);
    if (theme !== "system") return;
    // Track OS changes while on "system".
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => applyTheme("system");
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [theme]);

  const setTheme = (t: Theme) => {
    localStorage.setItem(STORAGE_KEY, t);
    setThemeState(t);
  };

  return <ThemeContext.Provider value={{ theme, setTheme }}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  return useContext(ThemeContext);
}
