#!/bin/sh
# Verify the break-glass token still works. See docs/deployment.md section 5.
#
# Run this quarterly. An untested recovery path is a belief, not a capability,
# and the failure it exists for is not the moment to discover the token was
# revoked in a cleanup eighteen months ago.
#
#   ORBIT_BREAK_GLASS=orbat_… make check-break-glass
#
# Exits non-zero on any problem, so it can be a cron job or a CI step. The token
# is never printed, never logged, and is passed through the environment rather
# than on the command line — an argument is visible in ps to every user on the
# box.
#
# POSIX sh and curl only. This has to run on a machine that may be having a bad
# day; depending on jq is one more thing that can be missing.

set -eu

URL="${ORBIT_URL:-http://localhost:8080}"
TOKEN="${ORBIT_BREAK_GLASS:-}"
# A break-glass credential should hold "*". Override to check a narrower one.
WANT_SCOPE="${ORBIT_EXPECT_SCOPE:-*}"
# Warn this far ahead of expiry. A break-glass token should not expire at all,
# but if one does, learning about it after the fact is the whole problem.
WARN_DAYS="${ORBIT_WARN_DAYS:-30}"

if [ -z "$TOKEN" ]; then
    echo "check-break-glass: set ORBIT_BREAK_GLASS to the token" >&2
    echo >&2
    echo "  ORBIT_BREAK_GLASS=\$(op read 'op://Private/Orbit break-glass/password') \\" >&2
    echo "      make check-break-glass" >&2
    exit 2
fi

body=$(mktemp)
trap 'rm -f "$body"' EXIT

# curl already writes 000 to -w on a connection failure and exits non-zero, so
# a "|| echo 000" fallback appends a second one and produces "000000".
code=$(curl -sS -o "$body" -w '%{http_code}' \
    --max-time 15 \
    -H "Authorization: Bearer $TOKEN" \
    "$URL/v1/whoami?format=text" 2>"$body.err") || true
[ -n "$code" ] || code=000

case "$code" in
000)
    echo "FAIL  cannot reach $URL" >&2
    sed 's/^/      /' "$body.err" >&2 2>/dev/null || true
    rm -f "$body.err"
    exit 1
    ;;
200) ;;
401)
    # The token authenticated once and does not now: revoked, expired, or the
    # database was restored from a backup that predates it.
    echo "FAIL  token rejected (401) — revoked, expired, or from a different deployment" >&2
    echo "      mint a replacement: orbitd token create -name break-glass -scopes '*'" >&2
    exit 1
    ;;
403)
    # Only reachable if /v1/whoami ever grows a scope requirement. Reported
    # distinctly because it means something different from a rejected token.
    echo "FAIL  token authenticated but was refused (403)" >&2
    exit 1
    ;;
*)
    echo "FAIL  unexpected status $code from $URL" >&2
    sed 's/^/      /' "$body" >&2
    exit 1
    ;;
esac
rm -f "$body.err"

name=$(sed -n 's/^name    *//p' "$body")
scopes=$(sed -n 's/^scopes  *//p' "$body")
expires=$(sed -n 's/^expires  *//p' "$body")

# Authenticating is not enough. A token whose scopes were narrowed still
# returns 200 here, and would fail at the moment it was needed.
if [ "$WANT_SCOPE" != "" ]; then
    case ",$(echo "$scopes" | tr -d ' ')," in
    *",$WANT_SCOPE,"*) ;;
    *)
        echo "FAIL  token no longer holds '$WANT_SCOPE' (has: $scopes)" >&2
        exit 1
        ;;
    esac
fi

status=0
case "$expires" in
never|"")
    ;;
*)
    days=$(echo "$expires" | sed -n 's/.*(\([-0-9]*\) days).*/\1/p')
    if [ -n "$days" ] && [ "$days" -le "$WARN_DAYS" ]; then
        echo "WARN  expires in $days days — a break-glass token should not expire" >&2
        status=1
    fi
    ;;
esac

echo "OK    break-glass token valid"
echo "      name    ${name:-(unnamed)}"
echo "      scopes  $scopes"
echo "      expires ${expires:-never}"
exit $status
