#!/usr/bin/env python3
"""Screenshot the admin UI, and measure whether it can be read.

Two things a typecheck and a linter cannot tell you: whether a page is laid out
the way you meant, and whether the text on it has enough contrast to read. This
does both, over the Chrome DevTools Protocol against a real browser.

The contrast half matters more than the screenshot half. "Looks fine" is not a
measurement, and the failures it misses are exactly the ones that only affect
somebody else — a theme you do not use, a screen you do not have.

    uishot.py --path /directory/hosts --out hosts.png
    uishot.py --path /directory/hosts --theme dark --contrast

Needs a session. Seed one the way the end-to-end suite does and pass the token:

    --token "$(cat session-token)"

Standard library plus websocket-client, deliberately: this is a development
tool and dragging a browser-automation framework in to take a picture would be
a larger dependency than the thing it checks.
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import time
from urllib.request import urlopen

try:
    import websocket  # type: ignore
except ImportError:
    sys.exit("uishot: pip install websocket-client")


# ---------------------------------------------------------------------------
# Contrast
# ---------------------------------------------------------------------------

def _channel(value: float) -> float:
    """One sRGB channel, linearised. The WCAG 2.x definition."""
    value /= 255
    return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4


def luminance(rgb: tuple[float, float, float]) -> float:
    r, g, b = (_channel(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(fg: tuple[float, float, float], bg: tuple[float, float, float]) -> float:
    a, b = luminance(fg), luminance(bg)
    lighter, darker = max(a, b), min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


def parse_rgb(value: str) -> tuple[float, float, float] | None:
    """Parse an `rgb()`/`rgba()` string.

    Only that form, because the page normalises everything else before it gets
    here. It did not always: the first version of this tool parsed what
    getComputedStyle returned, silently skipped anything that did not start with
    "rgb", and reported "all meet WCAG AA" for a page whose palette is entirely
    oklch — so it had checked almost nothing and said so in the voice of a pass.
    Normalising in the browser and counting what cannot be parsed are both
    answers to that.
    """
    value = value.strip()
    if not value.startswith("rgb"):
        return None
    inner = value[value.index("(") + 1 : value.rindex(")")]
    parts = [p.strip() for p in inner.replace("/", " ").replace(",", " ").split()]
    try:
        nums = [float(p) for p in parts[:3]]
    except ValueError:
        return None
    return (nums[0], nums[1], nums[2])


# ---------------------------------------------------------------------------
# CDP
# ---------------------------------------------------------------------------


class ToolError(Exception):
    """Something went wrong with the browser, as opposed to with the page.

    Exits 2, so a caller can tell "could not check" from "checked, and it
    fails" — which is the same distinction the contrast report itself makes
    between skipped and passing.
    """


class Browser:
    def __init__(self, port: int, width: int, height: int):
        self.proc = subprocess.Popen(
            [
                self._chromium(),
                "--headless=new",
                f"--remote-debugging-port={port}",
                "--remote-allow-origins=*",
                "--no-sandbox",
                "--disable-gpu",
                "--hide-scrollbars",
                f"--window-size={width},{height}",
                # The stack is only reachable on the gateway, and the names are
                # in /etc/hosts on a developer machine and nowhere in CI. This
                # makes the browser agree without either.
                "--host-resolver-rules=MAP *.cardinal.test 127.0.0.1",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        version = self._wait(port)
        self.ws = websocket.create_connection(version["webSocketDebuggerUrl"], timeout=30)
        self.n = 0
        target = self.send("Target.createTarget", url="about:blank")
        self.session = self.send(
            "Target.attachToTarget", targetId=target["targetId"], flatten=True
        )["sessionId"]

    @staticmethod
    def _chromium() -> str:
        for name in ("chromium", "chromium-browser", "google-chrome"):
            from shutil import which

            if path := which(name):
                return path
        raise ToolError("no chromium on PATH")

    @staticmethod
    def _wait(port: int) -> dict:
        for _ in range(100):
            try:
                return json.load(urlopen(f"http://127.0.0.1:{port}/json/version"))
            except Exception:
                time.sleep(0.1)
        raise ToolError("chromium never came up")

    def send(self, method: str, session: bool = False, **params):
        self.n += 1
        message = {"id": self.n, "method": method, "params": params}
        if session:
            message["sessionId"] = self.session
        try:
            self.ws.send(json.dumps(message))
            while True:
                reply = json.loads(self.ws.recv())
                if reply.get("id") == self.n:
                    if "error" in reply:
                        raise ToolError(f"{method}: {reply['error']}")
                    return reply.get("result", {})
        except websocket.WebSocketException as err:
            # A browser that died is not a page that failed. Distinguishing
            # them is the whole point of the exit codes below: reporting a
            # crashed chromium as "this page does not meet AA" sends somebody
            # looking at a stylesheet for an hour.
            raise ToolError(f"{method}: the browser went away: {err}") from err

    def page(self, method: str, **params):
        return self.send(method, session=True, **params)

    def evaluate(self, expression: str):
        result = self.page(
            "Runtime.evaluate", expression=expression, returnByValue=True
        )
        return result.get("result", {}).get("value")

    def close(self):
        try:
            self.ws.close()
        finally:
            self.proc.kill()


# Every text-bearing element worth checking, and its background.
#
# Walking the whole tree would report thousands of pairs, almost all of them the
# same few tokens. This asks about what a person actually reads.
PROBE = r"""
(() => {
  const seen = new Map();
  const interesting = document.querySelectorAll(
    'h1, h2, h3, p, a, button, td, th, span, label, li, div');

  // Every modern palette is authored in oklch, and getComputedStyle hands it
  // straight back — including through color-mix and opacity, which produce
  // oklab. Reading fillStyle back does not help: Chrome serialises wide-gamut
  // colours in the form they were written.
  //
  // So the colour is painted and the pixel read. Whatever the browser
  // understood, this is the sRGB it actually put on the screen, which is also
  // the only thing a contrast ratio can be computed from.
  const canvas = document.createElement('canvas');
  canvas.width = canvas.height = 1;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  const rgb = (colour) => {
    if (!colour) return colour;
    if (colour.startsWith('rgb')) return colour;
    // Cleared first: a colour the browser cannot parse leaves fillStyle
    // untouched, and without this the previous colour would be reported as
    // though it were this one.
    ctx.clearRect(0, 0, 1, 1);
    ctx.fillStyle = '#000';
    ctx.fillStyle = colour;
    ctx.fillRect(0, 0, 1, 1);
    const [r, g, b, a] = ctx.getImageData(0, 0, 1, 1).data;
    return a === 255 ? `rgb(${r}, ${g}, ${b})` : `rgba(${r}, ${g}, ${b}, ${a / 255})`;
  };

  const parse = (colour) => {
    const m = /rgba?\(([^)]+)\)/.exec(colour || '');
    if (!m) return null;
    const n = m[1].split(/[,\s/]+/).filter(Boolean).map(Number);
    return { r: n[0], g: n[1], b: n[2], a: n.length > 3 ? n[3] : 1 };
  };

  const backdrop = (el) => {
    // What is actually behind the text, composited.
    //
    // Walking to the first non-transparent ancestor is not enough: a
    // translucent overlay — a table header at 5% white, a hovered row — is a
    // real background and comparing against it raw reports 2.67:1 for text that
    // is perfectly legible, because the page behind it was never mixed in.
    const layers = [];
    for (let node = el; node; node = node.parentElement) {
      const layer = parse(rgb(getComputedStyle(node).backgroundColor));
      if (!layer || layer.a === 0) continue;
      layers.push(layer);
      if (layer.a === 1) break;
    }
    const base = parse(rgb(getComputedStyle(document.body).backgroundColor))
      || { r: 255, g: 255, b: 255, a: 1 };
    if (layers.length === 0 || layers[layers.length - 1].a !== 1) layers.push(base);

    // Back to front, so each translucent layer mixes into what it sits on.
    let out = layers[layers.length - 1];
    for (let i = layers.length - 2; i >= 0; i--) {
      const top = layers[i];
      out = {
        r: Math.round(top.r * top.a + out.r * (1 - top.a)),
        g: Math.round(top.g * top.a + out.g * (1 - top.a)),
        b: Math.round(top.b * top.a + out.b * (1 - top.a)),
        a: 1,
      };
    }
    return `rgb(${out.r}, ${out.g}, ${out.b})`;
  };

  for (const el of interesting) {
    const text = (el.textContent || '').trim();
    if (!text || el.children.length > 0) continue;
    const style = getComputedStyle(el);
    if (style.visibility === 'hidden' || style.display === 'none') continue;
    const box = el.getBoundingClientRect();
    if (box.width < 2 || box.height < 2) continue;

    const colour = rgb(style.color);
    const behind = backdrop(el);
    const key = colour + '|' + behind + '|' + style.fontSize + '|' + style.fontWeight;
    if (seen.has(key)) continue;
    seen.set(key, {
      sample: text.slice(0, 40),
      color: colour,
      background: behind,
      fontSize: parseFloat(style.fontSize),
      fontWeight: parseInt(style.fontWeight, 10) || 400,
    });
  }
  return [...seen.values()];
})()
"""


def required(size_px: float, weight: int) -> float:
    """WCAG AA. Large text is 18.66px bold or 24px, and gets a lower bar."""
    large = size_px >= 24 or (size_px >= 18.66 and weight >= 700)
    return 3.0 if large else 4.5


def split_fill(pair: str) -> tuple[str, str]:
    """Splits SELECTOR=VALUE on the separator, not on the selector's own `=`.

    `input[placeholder="nightly export"]=hello` has two equals signs and only
    the second one is the separator. Splitting naively on the first produced a
    selector that matched nothing — which the tool then reported, so the failure
    was loud rather than a screenshot of an empty form.

    Bracket depth is enough: CSS puts attribute comparisons inside `[...]` and
    nothing else in a selector uses `=`.
    """
    depth = 0
    for i, char in enumerate(pair):
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        elif char == "=" and depth == 0:
            return pair[:i], pair[i + 1:]
    raise ToolError(f"--fill needs SELECTOR=VALUE, got {pair!r}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base",
                    default="https://id.cardinal.test:"
                            + os.environ.get("CARDINAL_PORT", "8443"))
    ap.add_argument("--path", default="/")
    ap.add_argument("--out", help="write a PNG here")
    ap.add_argument("--theme", choices=["light", "dark"], default="light")
    ap.add_argument("--token", default=os.environ.get("CARDINAL_SESSION", ""),
                    help="session cookie value")
    ap.add_argument("--search", default="", help="type this into a search box first")
    ap.add_argument("--fill", action="append", default=[], metavar="SELECTOR=VALUE",
                    help="type VALUE into SELECTOR before measuring; repeatable. "
                         "Reaching a form's error state needs this: submitting "
                         "an empty form is one way, and submitting a filled-in "
                         "one that fails a rule is the other, and neither is "
                         "the state a page loads in.")
    ap.add_argument("--click", action="append", default=[], metavar="SELECTOR",
                    help="click this before measuring; repeatable, in order. "
                         "Reaches UI that only exists after an interaction — a "
                         "confirmation, a dialog, a destructive button. Without "
                         "it the sweep only ever sees a page's opening state, "
                         "and the colours most likely to be wrong are the ones "
                         "used least.")
    ap.add_argument("--contrast", action="store_true",
                    help="measure text contrast and fail on anything below AA")
    ap.add_argument("--width", type=int, default=1400)
    ap.add_argument("--height", type=int, default=900)
    ap.add_argument("--port", type=int, default=int(os.environ.get("CDP_PORT", "9422")))
    ap.add_argument("--settle", type=float, default=4.0,
                    help="seconds to wait for the page to finish loading")
    args = ap.parse_args()

    browser = Browser(args.port, args.width, args.height)
    try:
        browser.page("Page.enable")
        browser.page("Network.enable")
        # The viewport, set explicitly rather than left to --window-size.
        #
        # Chrome clamps a window to roughly 500px wide, so asking for a 375px
        # one silently gave a 500px one and every narrow screenshot was of a
        # screen no phone has. Found while checking whether the site overflowed
        # on a phone: it reported an overflow that was the tool's, not the
        # site's.
        browser.page(
            "Emulation.setDeviceMetricsOverride",
            width=args.width,
            height=args.height,
            deviceScaleFactor=1,
            # False, so a page wider than the viewport shows as a page wider
            # than the viewport. With mobile emulation Chrome scales it down to
            # fit, which is how a layout problem disappears from a screenshot.
            mobile=False,
        )
        browser.page(
            "Emulation.setEmulatedMedia",
            media="screen",
            features=[{"name": "prefers-color-scheme", "value": args.theme}],
        )
        if args.token:
            host = args.base.split("//", 1)[1].split(":")[0]
            browser.page("Network.setCookie", name="cardinal_session",
                         value=args.token, domain=host, path="/")

        browser.page("Page.navigate", url=args.base + args.path)
        time.sleep(args.settle)

        if args.search:
            # Typed rather than driven from the URL: paging and search live in
            # React state, so a filtered table cannot be reached by navigating.
            browser.evaluate("""
              (() => {
                const box = document.querySelector('input[type="search"], input[placeholder^="Search"]');
                if (!box) return 'no search box';
                const set = Object.getOwnPropertyDescriptor(
                  window.HTMLInputElement.prototype, 'value').set;
                set.call(box, %s);
                box.dispatchEvent(new Event('input', { bubbles: true }));
                return 'ok';
              })()
            """ % json.dumps(args.search))
            time.sleep(2)

        for pair in args.fill:
            selector, value = split_fill(pair)
            # The native setter, then an input event — React tracks the value on
            # the DOM node and ignores a plain assignment, so setting .value
            # directly leaves the component's state untouched and the form
            # submits empty while the screenshot shows text in the box.
            got = browser.evaluate("""
              (() => {
                const el = document.querySelector(%s);
                if (!el) return 'missing';
                const proto = el instanceof window.HTMLTextAreaElement
                  ? window.HTMLTextAreaElement.prototype
                  : window.HTMLInputElement.prototype;
                Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, %s);
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('blur', { bubbles: true }));
                return 'ok';
              })()
            """ % (json.dumps(selector), json.dumps(value)))
            if got != "ok":
                print(f"nothing matched {selector!r}", file=sys.stderr)
                return 2
            time.sleep(0.3)

        for selector in args.click:
            # A missing selector is fatal rather than skipped. A sweep that
            # silently fails to reach the state it was asked for reports "all
            # pass" about a button it never rendered, which is the failure mode
            # this whole tool exists to avoid.
            got = browser.evaluate("""
              (() => {
                const el = document.querySelector(%s);
                if (!el) return 'missing';
                el.click();
                return 'ok';
              })()
            """ % json.dumps(selector))
            if got != "ok":
                print(f"nothing matched {selector!r}", file=sys.stderr)
                return 2
            time.sleep(0.5)

        if args.out:
            shot = browser.page("Page.captureScreenshot", format="png",
                                captureBeyondViewport=True)
            with open(args.out, "wb") as f:
                f.write(base64.b64decode(shot["data"]))
            print(f"wrote {args.out}")

        if not args.contrast:
            return 0

        pairs = browser.evaluate(PROBE) or []
        failures = []
        unreadable = []
        for pair in pairs:
            fg, bg = parse_rgb(pair["color"]), parse_rgb(pair["background"])
            if fg is None or bg is None:
                # Reported, never skipped. A checker that quietly ignores what
                # it cannot parse says "all pass" about a page it did not look
                # at, which is worse than having no checker at all.
                unreadable.append(pair)
                continue
            ratio = contrast(fg, bg)
            need = required(pair["fontSize"], pair["fontWeight"])
            if ratio < need:
                failures.append((ratio, need, pair))

        checked = len(pairs) - len(unreadable)
        print(f"\n{args.theme}: {checked} of {len(pairs)} text/background pairs checked")

        for pair in unreadable:
            print(f"  ?      could not parse {pair['color']} on {pair['background']}")
            print(f"          \u201c{pair['sample']}\u201d")

        if not failures and not unreadable:
            print("  all meet WCAG AA")
            return 0
        if not failures:
            print(f"  no failures among the {checked} checked, but "
                  f"{len(unreadable)} could not be measured")
            return 1

        failures.sort(key=lambda f: f[0])
        for ratio, need, pair in failures:
            print(f"  {ratio:5.2f}:1 (need {need}) {pair['fontSize']:.0f}px "
                  f"w{pair['fontWeight']}  {pair['color']} on {pair['background']}")
            print(f"          “{pair['sample']}”")
        return 1
    finally:
        browser.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ToolError as err:
        print(f"uishot: {err}", file=sys.stderr)
        raise SystemExit(2) from err
