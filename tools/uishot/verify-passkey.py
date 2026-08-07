#!/usr/bin/env python3
"""Register a passkey and sign in with it, in a real browser.

The one thing no Go test can do. WebAuthn's failure modes are browser-side —
secure contexts, relying-party identifiers, origin checks, user verification —
and every one of them is invisible to a suite that crafts JSON and posts it.

Chrome's DevTools Protocol has a virtual authenticator, so the ceremony is real
in every respect except the hardware: the browser builds the client data, checks
the origin against the relying party, signs, and Cardinal verifies it the same
way it would verify a YubiKey.

This existed only after the example stack moved to TLS. It could not have run
before: WebAuthn needs a secure context, and the stack's own hostnames could not
provide one alongside the parent-domain cookie single sign-on requires. That
`window.PublicKeyCredential` was undefined on the enrollment page was, for
months, something nothing checked.

    verify-passkey.py --invite 'https://id.cardinal.test:8443/enroll?token=…'

Exits 0 when a passkey was registered and then used to sign in, 1 when the
ceremony failed, 2 when the browser could not be driven at all.
"""

import argparse
import json
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])

from uishot import Browser, ToolError  # noqa: E402


def step(message: str) -> None:
    print(f"== {message}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--invite", required=True, help="a single-use enrollment URL")
    ap.add_argument("--base", default="https://id.cardinal.test:8443")
    ap.add_argument("--login", required=True, help="the account the invite is for")
    ap.add_argument("--port", type=int, default=9820)
    args = ap.parse_args()

    browser = Browser(args.port, 1400, 900)
    try:
        browser.page("Page.enable")
        browser.page("Network.enable")

        # A secure context is the precondition for all of it, and checking it
        # first turns "the ceremony silently did nothing" into one clear line.
        browser.page("Page.navigate", url=args.base + "/")
        time.sleep(4)
        if not browser.evaluate("window.isSecureContext"):
            print(f"{args.base} is not a secure context, so WebAuthn does not "
                  f"exist there. Serve it over HTTPS with a trusted certificate.",
                  file=sys.stderr)
            return 1
        if browser.evaluate("typeof window.PublicKeyCredential") != "function":
            print("PublicKeyCredential is undefined — no passkey can be "
                  "registered from this origin.", file=sys.stderr)
            return 1
        step("the origin is a secure context and exposes WebAuthn")

        # ctap2 with user verification, which is what a platform authenticator
        # or a modern security key presents. isUserVerified true stands in for
        # the fingerprint nobody is here to give.
        browser.page("WebAuthn.enable")
        authenticator = browser.page("WebAuthn.addVirtualAuthenticator", options={
            "protocol": "ctap2",
            "transport": "internal",
            "hasResidentKey": True,
            "hasUserVerification": True,
            "isUserVerified": True,
            "automaticPresenceSimulation": True,
        })["authenticatorId"]
        step("attached a virtual authenticator")

        browser.page("Page.navigate", url=args.invite)
        time.sleep(4)

        # The enrollment page refuses to render the form at all when passkeys
        # are unavailable, so reaching the submit button is itself an assertion.
        filled = browser.evaluate("""
          (() => {
            const set = Object.getOwnPropertyDescriptor(
              window.HTMLInputElement.prototype, 'value').set;
            const inputs = document.querySelectorAll('form input');
            if (inputs.length < 2) return 'no form';
            set.call(inputs[0], 'Passkey Check');
            inputs[0].dispatchEvent(new Event('input', { bubbles: true }));
            set.call(inputs[2] || inputs[1], 'virtual key');
            (inputs[2] || inputs[1]).dispatchEvent(new Event('input', { bubbles: true }));
            return 'ok';
          })()
        """)
        if filled != "ok":
            print(f"could not fill the enrollment form: {filled}", file=sys.stderr)
            return 1

        browser.evaluate("document.querySelector('form button[type=submit]').click()")
        time.sleep(6)

        credentials = browser.page(
            "WebAuthn.getCredentials", authenticatorId=authenticator)["credentials"]
        if not credentials:
            body = browser.evaluate("document.body.innerText")
            print(f"no credential was created. The page says:\n{body}", file=sys.stderr)
            return 1
        step(f"registered {len(credentials)} passkey, resident={credentials[0]['isResidentCredential']}")

        # Registering is half of it. A credential that cannot then authenticate
        # is a credential that locked somebody out, so the sign-in is the
        # assertion that matters.
        browser.page("Network.clearBrowserCookies")
        browser.page("Page.navigate", url=args.base + "/")
        time.sleep(4)

        clicked = browser.evaluate("""
          (() => {
            const button = [...document.querySelectorAll('button')]
              .find((b) => /sign in|passkey/i.test(b.textContent || ''));
            if (!button) return 'no sign-in button';
            button.click();
            return 'ok';
          })()
        """)
        if clicked != "ok":
            print(f"could not start sign-in: {clicked}", file=sys.stderr)
            return 1
        time.sleep(6)

        # Synchronous XHR rather than fetch: Runtime.evaluate does not await a
        # promise unless asked to, so a fetch returns a pending object and the
        # check silently passes on nothing.
        who = browser.evaluate("""
          (() => {
            const r = new XMLHttpRequest();
            r.open('GET', '/api/auth/me', false);
            r.setRequestHeader('Accept', 'application/json');
            r.send(null);
            if (r.status !== 200) return 'not signed in (' + r.status + ')';
            const me = JSON.parse(r.responseText);
            return me.login + '|' + me.authMethod + '|' + me.deviceBound;
          })()
        """)
        if "|" not in who:
            print(f"signing in with the passkey failed: {who}", file=sys.stderr)
            return 1

        login, method, bound = who.split("|")
        step(f"signed in as {login} via {method}, deviceBound={bound}")
        if login != args.login:
            print(f"signed in as {login}, expected {args.login}", file=sys.stderr)
            return 1

        # The session that login just created must record where it came from.
        #
        # client_ip and user_agent have been columns since the first migration
        # and nothing ever wrote them. Only a real login can populate them, and
        # the only credential Cardinal accepts is a passkey — so this is the
        # only place the write path can be checked at all. The Go suite covers
        # the read half against seeded values and says so.
        listing = browser.evaluate("""
          (() => {
            const r = new XMLHttpRequest();
            r.open('GET', '/api/sessions', false);
            r.setRequestHeader('Accept', 'application/json');
            r.send(null);
            if (r.status !== 200) return 'error ' + r.status;
            const here = JSON.parse(r.responseText).sessions.find((s) => s.current);
            if (!here) return 'no current session in the listing';
            return JSON.stringify({ ip: here.clientIp, agent: here.userAgent });
          })()
        """)
        if listing.startswith(("error", "no current")):
            print(f"could not read the session listing: {listing}", file=sys.stderr)
            return 1

        origin = json.loads(listing)
        if not origin["ip"] or not origin["agent"]:
            print(f"the session recorded no origin: {origin}. Both columns have "
                  f"existed since the first migration; something is not writing "
                  f"them.", file=sys.stderr)
            return 1
        step(f"the session records {origin['ip']}, "
             f"{origin['agent'][:40]}…")

        print()
        print("PASS: a passkey was registered in a real browser and then used to")
        print("      sign in — the ceremony, the origin check and the signature")
        print("      all verified by something other than Cardinal's own tests")
        return 0
    except ToolError as err:
        print(f"could not drive the browser: {err}", file=sys.stderr)
        return 2
    finally:
        browser.close()


if __name__ == "__main__":
    sys.exit(main())
