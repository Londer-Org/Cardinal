#!/usr/bin/env bash
# Sweep every admin page in both themes and fail on anything below WCAG AA.
#
# Needs the end-to-end stack (`make e2e-up`) and a chromium on PATH. Seeds its
# own session the way the end-to-end suite does — a throwaway administrator in a
# throwaway container, not a credential.
set -euo pipefail

cd "$(dirname "$0")/../.."

COMPOSE="docker compose -f examples/compose.yml"
PSQL="$COMPOSE exec -T postgres psql -U cardinal -d cardinal"
TOKEN="uishot-session-token-with-plenty-of-entropy-0123456789"
BASE="${BASE:-https://id.cardinal.test:8443}"

PYTHON="${PYTHON:-python3}"
if ! "$PYTHON" -c "import websocket" 2>/dev/null; then
    echo "uishot needs websocket-client:" >&2
    echo "  python3 -m venv .venv && .venv/bin/pip install websocket-client" >&2
    echo "  PYTHON=.venv/bin/python $0" >&2
    exit 1
fi

$PSQL -q -c "INSERT INTO entities (type, name, display_name)
             VALUES ('user','uishot','Contrast Check')
             ON CONFLICT (type,name) DO UPDATE SET disabled_at = NULL" >/dev/null
$PSQL -q -c "INSERT INTO group_members (group_id, member_id, granted_by, valid_period)
             SELECT '00000000-0000-7000-8000-00000000ad11', e.id, e.id,
                    tstzrange(now(),'infinity')
               FROM entities e WHERE e.name='uishot'
             ON CONFLICT DO NOTHING" >/dev/null
$PSQL -q -c "DELETE FROM sessions WHERE token_hash = sha256('$TOKEN'::bytea)" >/dev/null
$PSQL -q -c "INSERT INTO sessions (subject_id, token_hash, valid_period, auth_method,
                                   auth_at, device_bound, absolute_expiry)
             SELECT e.id, sha256('$TOKEN'::bytea),
                    tstzrange(now(), now()+interval '1 hour'), 'passkey', now(),
                    true, now()+interval '1 day'
               FROM entities e WHERE e.name='uishot'" >/dev/null

# A token, so /access/tokens has a row to interact with rather than an empty
# state. The hash is of a value nothing knows, which is the point: this exists
# to be listed and clicked, never to authenticate.
# A host with an alias and a group, so the detail page has something on every
# panel rather than four empty states.
$PSQL -q -c "INSERT INTO entities (type, name, display_name)
             VALUES ('host','uishot-web.prod','Contrast host')
             ON CONFLICT (type,name) DO NOTHING" >/dev/null
$PSQL -q -c "INSERT INTO host_aliases (host_id, name)
             SELECT e.id, 'uishot-web.example.com' FROM entities e
              WHERE e.name='uishot-web.prod'
             ON CONFLICT DO NOTHING" >/dev/null

$PSQL -q -c "INSERT INTO access_tokens (subject_id, name, token_hash, prefix,
                                        valid_period, created_by)
             SELECT e.id, 'nightly export', sha256('uishot-fixture'::bytea),
                    'crd_pat_uishot', tstzrange(now(), now()+interval '90 days'), e.id
               FROM entities e WHERE e.name='uishot'
             ON CONFLICT (token_hash) DO NOTHING" >/dev/null

# A second session, so /account shows a list with a revocable row rather than
# one entry nobody may end. The user agent is a real Safari string, which is
# what exercises the description heuristic — every Chromium browser also claims
# to be Safari, so the ordering in describeAgent matters.
$PSQL -q -c "INSERT INTO sessions (subject_id, token_hash, valid_period, auth_method,
                                   auth_at, device_bound, absolute_expiry,
                                   client_ip, user_agent)
             SELECT e.id, sha256('uishot-second-device'::bytea),
                    tstzrange(now() - interval '2 hours', now() + interval '5 hours'),
                    'passkey', now() - interval '2 hours', false,
                    now() + interval '6 days', '198.51.100.24'::inet,
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15'
               FROM entities e WHERE e.name='uishot'
             ON CONFLICT (token_hash) DO NOTHING" >/dev/null

# path, then any selectors to click before measuring. Anything that only exists
# after an interaction is invisible to a sweep that just navigates — and the
# colours used least are the ones most likely to be wrong, because nobody has
# looked at them. The destructive button was 3.81:1 in dark for exactly that
# reason: a page-only sweep never rendered one.
PAGES=(
  /
  /account
  # The revoke confirmation on a session row: a destructive button and a
  # cancel, neither of which exists until somebody clicks.
  "/account|button.text-destructive"
  /access/passkeys
  /access/tokens
  "/access/tokens|button.text-destructive"
  # Submitting empty puts the form into its error state: red label, red border,
  # red message. None of that exists on a page as it loads, and red on a card is
  # exactly the pair that was failing in dark.
  "/access/tokens|button[type=\"submit\"]"
  /access/connected
  /access/decisions
  /directory/people
  /directory/groups
  /directory/hosts
  /directory/hosts/uishot-web.prod
  /directory/recovery
  /integrations/applications
)

port=9600
failed=0
errored=0
for entry in "${PAGES[@]}"; do
    path="${entry%%|*}"
    clicks=()
    if [ "$entry" != "$path" ]; then
        IFS='|' read -r -a selectors <<< "${entry#*|}"
        for selector in "${selectors[@]}"; do
            clicks+=(--click "$selector")
        done
    fi
    label="$path${entry#"$path"}"

    for theme in light dark; do
        port=$((port + 1))
        out=$("$PYTHON" tools/uishot/uishot.py --base "$BASE" --path "$path" \
                 --theme "$theme" --token "$TOKEN" --contrast "${clicks[@]}" \
                 --port "$port" 2>&1) && status=0 || status=$?

        case "$status" in
            0)  printf '  ok    %-5s %s\n' "$theme" "$label" ;;
            2)  # The browser fell over, which says nothing about the page. Once
                # more before deciding, because these are almost always a
                # chromium that did not come up in time.
                port=$((port + 1))
                if out=$("$PYTHON" tools/uishot/uishot.py --base "$BASE" --path "$path" \
                            --theme "$theme" --token "$TOKEN" --contrast "${clicks[@]}" \
                            --port "$port" 2>&1); then
                    printf '  ok    %-5s %s (after a retry)\n' "$theme" "$label"
                else
                    printf '  ERROR %-5s %s — could not check\n' "$theme" "$label"
                    echo "$out" | sed 's/^/        /'
                    errored=$((errored + 1))
                fi ;;
            *)  printf '  FAIL  %-5s %s\n' "$theme" "$label"
                echo "$out" | sed 's/^/        /'
                failed=$((failed + 1)) ;;
        esac
    done
done

echo
if [ "$failed" -gt 0 ]; then
    echo "$failed page/theme combination(s) below WCAG AA"
    exit 1
fi
if [ "$errored" -gt 0 ]; then
    # Never a pass. "I could not look" and "I looked and it was fine" are
    # different answers, and collapsing them is how a check stops catching
    # things without anybody noticing.
    echo "$errored could not be checked at all"
    exit 2
fi
echo "every page reads in both themes"
