/**
 * cn() — class name combiner used by the shadcn-style UI components.
 *
 * Lightweight stand-in for clsx + tailwind-merge: joins truthy class
 * fragments. If/when conflicting Tailwind classes become a problem, swap the
 * body for `twMerge(clsx(...inputs))` without changing any call site.
 */
export type ClassValue = string | number | null | false | undefined;

export function cn(...inputs: ClassValue[]): string {
  return inputs.filter(Boolean).join(" ");
}
