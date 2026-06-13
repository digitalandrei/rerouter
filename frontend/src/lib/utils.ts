/**
 * cn() — class name combiner used by the shadcn UI components.
 *
 * clsx joins truthy class fragments; tailwind-merge resolves conflicting
 * Tailwind utilities (last one wins), so component callers can safely
 * override defaults via the `className` prop.
 */
import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
