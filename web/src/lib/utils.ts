import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/**
 * Merges class names, resolving Tailwind conflicts in favour of the last value.
 *
 * Required by the vendored shadcn/ui components: without it, a `className` prop
 * passed to a component would sit alongside the component's own classes rather
 * than overriding them, and which one wins would come down to CSS source order.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}
