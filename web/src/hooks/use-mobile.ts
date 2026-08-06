import * as React from 'react'

const MOBILE_BREAKPOINT = 768

// From shadcn/ui, adapted to this repo's strict lint: lazy initial state (a
// client-only SPA, so `window` is available) instead of a synchronous setState
// inside the effect, and a braced cleanup.
export function useIsMobile() {
  const [isMobile, setIsMobile] = React.useState(() => window.innerWidth < MOBILE_BREAKPOINT)

  React.useEffect(() => {
    const mql = window.matchMedia(`(max-width: ${String(MOBILE_BREAKPOINT - 1)}px)`)
    const onChange = () => {
      setIsMobile(window.innerWidth < MOBILE_BREAKPOINT)
    }
    mql.addEventListener('change', onChange)
    return () => {
      mql.removeEventListener('change', onChange)
    }
  }, [])

  return isMobile
}
