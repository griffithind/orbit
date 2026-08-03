#!/bin/sh
# Regenerate THIRD-PARTY-NOTICES.md from the modules actually in the build.
#
# Driven by `go list -m all` rather than by a hand-kept list, because a
# hand-kept list is wrong the first time a dependency changes and nothing
# notices. Run it after any go.mod change:
#
#   make third-party
#
# Apache-2.0 dependencies are called out separately: that licence requires the
# notice to travel with a binary distribution, so the released tarballs carry
# this file.
set -eu

cd "$(dirname "$0")/.."

out=THIRD-PARTY-NOTICES.md

classify() {
    # $1 is a licence file. Order matters: several MIT texts mention other
    # licences in passing, so match the distinctive headline first.
    if grep -qi "Apache License" "$1"; then echo "Apache-2.0"; return; fi
    if grep -qi "ISC License" "$1"; then echo "ISC"; return; fi
    if grep -qi "BSD 3-Clause" "$1"; then echo "BSD-3-Clause"; return; fi
    if grep -qi "Redistribution and use in source and binary forms" "$1"; then
        echo "BSD"; return
    fi
    if grep -qi "Permission is hereby granted, free of charge" "$1"; then
        echo "MIT"; return
    fi
    echo "UNKNOWN"
}

{
    cat <<'HEADER'
# Third-party notices

Orbit is MIT licensed. It links the modules below, each under its own
permissive licence. No dependency is copyleft.

Regenerate with `make third-party`.

| Module | Licence |
|---|---|
HEADER

    unknown=0
    for dir in $(go list -m -f '{{.Dir}}' all 2>/dev/null); do
        case "$dir" in
            ''|*griffithind/orbit) continue ;;
        esac
        path=$(go list -m -f '{{.Path}} {{.Dir}}' all 2>/dev/null |
            awk -v d="$dir" '$2 == d {print $1; exit}')
        [ -n "$path" ] || continue

        lic=""
        for candidate in LICENSE LICENSE.md LICENSE.txt LICENCE COPYING COPYING.md; do
            if [ -f "$dir/$candidate" ]; then lic="$dir/$candidate"; break; fi
        done
        if [ -z "$lic" ]; then
            echo "| \`$path\` | **NO LICENCE FILE — check before release** |"
            unknown=$((unknown + 1))
            continue
        fi
        kind=$(classify "$lic")
        [ "$kind" = "UNKNOWN" ] && unknown=$((unknown + 1))
        echo "| \`$path\` | $kind |"
    done | sort -u

    cat <<'FOOTER'

## Apache-2.0 attribution

The Apache License 2.0 requires its notice to accompany binary distributions.
The modules above marked Apache-2.0 are covered by that licence, whose full
text is at <https://www.apache.org/licenses/LICENSE-2.0>.
FOOTER
} > "$out"

echo "wrote $out"

# A licence this script could not classify is the one case worth failing on:
# silently filing it as "UNKNOWN" in a generated table is how a copyleft
# dependency gets shipped.
if grep -q "UNKNOWN\|NO LICENCE FILE" "$out"; then
    echo "error: unclassified licences in $out; classify them by hand before releasing" >&2
    exit 1
fi
