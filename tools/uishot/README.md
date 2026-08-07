# uishot

Screenshot the admin UI, and measure whether it can be read.

Two things a typecheck and a linter cannot tell you: whether a page is laid out
the way you meant, and whether the text on it has enough contrast to read.

```sh
python3 -m venv .venv && .venv/bin/pip install websocket-client

make e2e-up
PYTHON=.venv/bin/python tools/uishot/check-contrast.sh
```

## Why the contrast half exists

"Looks fine" is not a measurement, and the failures it misses are the ones that
only affect somebody else — a theme you do not use, a screen you do not have.

This project had one: the dark palette copied `--warning-foreground` from the
light one, which is a dark brown. On the dark card that is **1.11:1** — not
low-contrast, invisible. Nobody noticed because dark mode was unreachable until
the theme toggle landed, so the bug had been sitting in the stylesheet unread.

## Two bugs this tool had, both worth knowing about

It reported **"all meet WCAG AA"** for that page.

**It could not read the colours.** `getComputedStyle` returns oklch for an
oklch palette, the parser only understood `rgb()`, and anything else was
silently skipped — so it checked almost nothing and said so in the voice of a
pass. Colours are now painted to a 1×1 canvas and the pixel read back, which is
the sRGB the browser actually put on screen whatever the input format. And
anything still unparseable is *counted and printed*, never skipped: a checker
that quietly ignores what it cannot handle is worse than no checker.

**It compared against translucent backgrounds raw.** A table header at 5% white
over a dark page was treated as if it were 5% white over nothing, reporting
2.67:1 for text that is perfectly legible. Backgrounds are now composited down
the ancestor chain until something opaque is reached.

Both were found by looking at a screenshot and disagreeing with the tool.

## verify-passkey.py

The same browser, used for the one thing no Go test can do: registering a
passkey and signing in with it. Chrome's virtual authenticator makes the
ceremony real in every respect but the hardware — the browser builds the client
data, checks the origin against the relying party, and signs.

```
make verify-passkey
```

It could not run at all until the example stack moved to TLS. WebAuthn needs a
secure context, and the stack's hostnames could not offer one alongside the
parent-domain cookie single sign-on requires; `window.PublicKeyCredential` was
undefined on the enrollment page, and nothing checked.

## Usage

```
uishot.py --path /directory/hosts --out hosts.png
uishot.py --path /directory/hosts --theme dark --contrast
uishot.py --path /directory/hosts --search "web-01" --out filtered.png

# Reach a state the page does not load in
uishot.py --path /access/tokens --click 'button.text-destructive' --contrast
uishot.py --path /access/tokens --fill 'input[name="name"]=nightly' \
                                --click 'button[type="submit"]' --contrast
```

`--search` types into the page's search box rather than putting a query in the
URL, because paging and search live in React state — a filtered table cannot be
reached by navigating to one.

`--click` and `--fill` exist for the same reason, generalised. **A sweep that
only navigates measures a page's opening state, and the colours most likely to
be wrong are the ones used least — because nobody has looked at them.** The
destructive button sat at 3.81:1 in dark for as long as dark mode existed: it
only appears once somebody has clicked something, so no sweep had ever rendered
one. Form validation errors are the same, one interaction further in.

Both are repeatable and run in order. A selector that matches nothing is fatal
rather than skipped — a sweep that quietly failed to reach the state it was
asked for would report "all pass" about a button it never drew. `--fill` splits
on the `=` outside any brackets, so `input[placeholder="a b"]=value` works.

A session is needed for anything behind the sidebar; `check-contrast.sh` seeds
one, along with a token so `/access/tokens` has a row to interact with. Standard library plus `websocket-client`, deliberately: this is a
development tool, and pulling in a browser-automation framework to take a
picture would be a larger dependency than the thing it checks.
