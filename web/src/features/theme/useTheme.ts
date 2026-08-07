import { useCallback, useEffect, useSyncExternalStore } from 'react'

/**
 * Light, dark, or whatever the machine is set to.
 *
 * Three states rather than two, and the third is the default. Somebody who has
 * set their whole desktop dark has already expressed a preference, and an app
 * that ignores it until asked is one more thing to configure — but an app with
 * *only* a system default cannot be overridden by somebody who wants this one
 * page light while they screenshot it.
 */
export type Theme = 'light' | 'dark' | 'system'

const STORAGE_KEY = 'cardinal-theme'

function isTheme(value: unknown): value is Theme {
  return value === 'light' || value === 'dark' || value === 'system'
}

function stored(): Theme {
  // Never throws: localStorage is unavailable in some privacy modes, and a
  // theme preference is not worth a blank page.
  try {
    const value = window.localStorage.getItem(STORAGE_KEY)
    return isTheme(value) ? value : 'system'
  } catch {
    return 'system'
  }
}

const query = () => window.matchMedia('(prefers-color-scheme: dark)')

/** What the theme resolves to right now. */
function resolve(theme: Theme): 'light' | 'dark' {
  if (theme !== 'system') return theme
  return query().matches ? 'dark' : 'light'
}

/**
 * Apply the theme to the document.
 *
 * Tailwind's dark variant here is `&:is(.dark *)`, so the class has to be on an
 * ancestor of everything — which means the root element, and means portals
 * (dropdowns, dialogs) are covered too because they mount into document.body.
 */
function apply(theme: Theme) {
  const root = document.documentElement
  root.classList.toggle('dark', resolve(theme) === 'dark')
  // So the browser paints form controls and scrollbars to match rather than
  // leaving white boxes on a dark page.
  root.style.colorScheme = resolve(theme)
}

/**
 * Set before React runs, from index.html's inline script or from here on first
 * import. Without it the page paints light and then flips, which is the flash
 * every themed site is judged by.
 */
export function initTheme() {
  apply(stored())
}

// A tiny store rather than context: the theme is one value, read in two places,
// and changed rarely. A provider would be more moving parts for the same thing.
const listeners = new Set<() => void>()

function subscribe(listener: () => void) {
  listeners.add(listener)
  // The system preference can change while the page is open — somebody
  // switching their desktop at sunset — and a `system` theme that only updated
  // on reload would be wrong for as long as the tab stayed open.
  const media = query()
  const onSystemChange = () => {
    if (stored() === 'system') {
      apply('system')
      listeners.forEach((l) => { l() })
    }
  }
  media.addEventListener('change', onSystemChange)

  return () => {
    listeners.delete(listener)
    media.removeEventListener('change', onSystemChange)
  }
}

let snapshot: Theme = 'system'

function getSnapshot(): Theme {
  const current = stored()
  // useSyncExternalStore compares snapshots by identity, and returning a fresh
  // read every time would loop forever on a string that is equal but recomputed.
  if (current !== snapshot) snapshot = current
  return snapshot
}

/**
 * What to report when there is no `window` at all.
 *
 * A named function with a return type rather than an inline `as Theme`, which
 * tsc needs and eslint calls redundant — this satisfies both without either
 * being suppressed.
 */
function getServerSnapshot(): Theme {
  return 'system'
}

/** The theme, and a way to change it. */
export function useTheme() {
  const theme = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot)

  const setTheme = useCallback((next: Theme) => {
    try {
      window.localStorage.setItem(STORAGE_KEY, next)
    } catch {
      // Unstorable is not unusable: apply it for this page and move on.
    }
    snapshot = next
    apply(next)
    listeners.forEach((l) => { l() })
  }, [])

  // Covers the case where something else changed storage — another tab, or the
  // inline script running after this module was evaluated.
  useEffect(() => { apply(theme) }, [theme])

  return { theme, resolved: resolve(theme), setTheme }
}
