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
BASE="${BASE:-http://id.localhost:8100}"

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

PAGES=(
  /
  /account
  /access/passkeys
  /access/connected
  /access/decisions
  /directory/people
  /directory/groups
  /directory/hosts
  /directory/recovery
  /integrations/applications
)

port=9600
failed=0
errored=0
for path in "${PAGES[@]}"; do
    for theme in light dark; do
        port=$((port + 1))
        out=$("$PYTHON" tools/uishot/uishot.py --base "$BASE" --path "$path" \
                 --theme "$theme" --token "$TOKEN" --contrast --port "$port" 2>&1) && status=0 || status=$?

        case "$status" in
            0)  printf '  ok    %-5s %s\n' "$theme" "$path" ;;
            2)  # The browser fell over, which says nothing about the page. Once
                # more before deciding, because these are almost always a
                # chromium that did not come up in time.
                port=$((port + 1))
                if out=$("$PYTHON" tools/uishot/uishot.py --base "$BASE" --path "$path" \
                            --theme "$theme" --token "$TOKEN" --contrast --port "$port" 2>&1); then
                    printf '  ok    %-5s %s (after a retry)\n' "$theme" "$path"
                else
                    printf '  ERROR %-5s %s — could not check\n' "$theme" "$path"
                    echo "$out" | sed 's/^/        /'
                    errored=$((errored + 1))
                fi ;;
            *)  printf '  FAIL  %-5s %s\n' "$theme" "$path"
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
