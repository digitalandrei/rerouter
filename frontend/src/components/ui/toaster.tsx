import { Toaster as Sonner } from "sonner";
import { useTheme } from "@/lib/theme";

/** App toast host — temporary notifications in the top-right corner. */
export function Toaster() {
  const { theme } = useTheme();
  return <Sonner theme={theme} position="top-right" richColors closeButton />;
}
