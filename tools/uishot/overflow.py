#!/usr/bin/env python3
"""Find what makes a page wider than the screen it is on.

    PYTHON=.venv/bin/python tools/uishot/overflow.py --base http://localhost:3120 \
        --path / --width 375

A page that scrolls sideways on a phone is usually one element doing it — a
table, a pre, a grid that never collapses — and the rest of the layout is
blameless. Guessing which is slow and gets it wrong; the browser already knows.

Reports every element whose right edge is beyond the viewport, innermost first,
because the outermost ones are being stretched by the innermost one rather than
being the cause.
"""

from __future__ import annotations

import argparse
import sys
import time

from uishot import Browser  # the CDP session this reuses


PROBE = """
(() => {
  const limit = window.innerWidth;
  const out = [];
  for (const el of document.querySelectorAll('body *')) {
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) continue;
    const right = r.right + window.scrollX;
    if (right <= limit + 1) continue;
    // Elements that scroll their own overflow are containing it, which is the
    // fix rather than the fault — they are reported but marked.
    const style = getComputedStyle(el);
    const scrolls = ['auto', 'scroll'].includes(style.overflowX);
    out.push({
      tag: el.tagName.toLowerCase(),
      cls: (el.className && typeof el.className === 'string')
        ? el.className.split(/\\s+/).slice(0, 3).join('.')
        : '',
      width: Math.round(r.width),
      right: Math.round(right),
      scrolls,
      depth: (() => { let d = 0, n = el; while ((n = n.parentElement)) d++; return d; })(),
    });
  }
  return {
    viewport: limit,
    scrollWidth: document.documentElement.scrollWidth,
    offenders: out.sort((a, b) => b.depth - a.depth).slice(0, 12),
  };
})()
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:3000")
    ap.add_argument("--path", default="/")
    ap.add_argument("--width", type=int, default=375)
    ap.add_argument("--height", type=int, default=800)
    ap.add_argument("--port", type=int, default=9422)
    ap.add_argument("--settle", type=float, default=4.0)
    args = ap.parse_args()

    browser = Browser(args.port, args.width, args.height)
    try:
        browser.page("Page.enable")
        # The viewport is set here rather than by --window-size, which Chrome
        # clamps to about 500px: asking for a 375px window silently produced a
        # 500px one, so every measurement below that width was of a screen no
        # phone has. Measured that way first, and it reported the site
        # overflowing when it was the tool that was wrong.
        browser.page(
            "Emulation.setDeviceMetricsOverride",
            width=args.width,
            height=args.height,
            deviceScaleFactor=1,
            mobile=False,
        )
        browser.page("Page.navigate", url=args.base + args.path)
        # The same fixed settle uishot uses. A load event is not enough here:
        # the layout that overflows is often the one that arrives with the
        # font, and measuring before it lands reports a page that fits.
        time.sleep(args.settle)
        result = browser.evaluate(PROBE)
    finally:
        browser.close()

    print(f"{args.path}  viewport {result['viewport']}px  "
          f"scrollWidth {result['scrollWidth']}px")
    if result["scrollWidth"] <= result["viewport"]:
        print("  fits")
        return 0

    print("  innermost first — the first row is usually the cause:")
    for o in result["offenders"]:
        mark = "  (scrolls its own overflow)" if o["scrolls"] else ""
        name = f"{o['tag']}.{o['cls']}" if o["cls"] else o["tag"]
        print(f"    {name:<44} {o['width']:>5}px wide, right edge {o['right']:>5}px{mark}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
