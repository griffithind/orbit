#!/bin/sh
# Regenerate THIRD-PARTY-NOTICES.md.
#
#   make third-party
#
# WHAT IT LISTS, and why not `go list -m all`. The module graph contains many
# modules whose code is never compiled into anything we ship — build tooling,
# alternative platforms, transitive requirements of test dependencies. Listing
# them is not merely noise: a licence manifest is a statement about what is
# being distributed, and naming a module we do not distribute makes the whole
# document less believable, not more.
#
# So the set is computed from what actually links: `go list -deps` over every
# command, for every platform the release ships. The union across platforms
# matters because build tags decide real membership — vishvananda/netlink is in
# the Linux binaries and not the macOS ones.
#
# Determinism. Two things would otherwise make the output depend on the machine
# rather than on the code, and both have bitten this file:
#
#   - `.Dir` is empty for a module the local cache has not extracted, and an
#     empty field vanishes in word-splitting. That silently drops modules, so
#     the file differed between a developer's machine and a fresh CI runner.
#     `go mod download` fixes the cause; the empty-dir check below fails loudly
#     rather than skipping, in case it ever does not.
#   - sort collation differs between BSD and GNU sort. LC_ALL=C everywhere.
set -eu

cd "$(dirname "$0")/.."

export LC_ALL=C

out=THIRD-PARTY-NOTICES.md
tmp=$(mktemp)
mods=$(mktemp)
trap 'rm -f "$tmp" "$mods"' EXIT

# The release matrix, kept in step with .github/workflows/release.yml. orbitd
# and orbit-migrate are Linux-only there, but listing every command on every
# platform here is the conservative direction: it can only widen the set.
for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do
    GOOS="${target%/*}" GOARCH="${target#*/}" \
        go list -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' ./cmd/... 2>/dev/null
done | sort -u | grep -v '^$' | grep -v '^github.com/griffithind/orbit$' > "$mods"

# Extract every module we are about to describe, so .Dir resolves for all of
# them rather than for whichever ones this machine happened to have already.
xargs go mod download < "$mods"

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
    count=$(wc -l < "$mods" | tr -d ' ')
    cat <<HEADER
# Third-party notices

Orbit is MIT licensed. Its binaries link the $count modules below, each under
its own permissive licence. No dependency is copyleft.

This lists what is actually compiled into the released binaries, across every
platform they are built for — not the whole module graph, most of which is
build tooling and test-only requirements that ship in nothing.

Regenerate with \`make third-party\`.

| Module | Licence |
|---|---|
HEADER

    while IFS= read -r path; do
        dir=$(go list -m -f '{{.Dir}}' "$path" 2>/dev/null || true)
        if [ -z "$dir" ]; then
            echo "| \`$path\` | **UNRESOLVED — no module directory** |"
            continue
        fi
        lic=""
        for candidate in LICENSE LICENSE.md LICENSE.txt LICENCE COPYING COPYING.md; do
            if [ -f "$dir/$candidate" ]; then lic="$dir/$candidate"; break; fi
        done
        if [ -z "$lic" ]; then
            echo "| \`$path\` | **NO LICENCE FILE** |"
            continue
        fi
        echo "| \`$path\` | $(classify "$lic") |"
    done < "$mods"

    cat <<'FOOTER'

## Apache-2.0 attribution

The Apache License 2.0 requires its notice to accompany binary distributions.
The modules above marked Apache-2.0 are covered by that licence, whose full text
is at <https://www.apache.org/licenses/LICENSE-2.0>.
FOOTER
} > "$tmp"

# Anything unclassified is the one case worth failing on. Filing it quietly in a
# generated table nobody re-reads is how a copyleft dependency gets shipped.
if grep -q "UNKNOWN\|NO LICENCE FILE\|UNRESOLVED" "$tmp"; then
    echo "error: unclassified licences — resolve these before releasing:" >&2
    grep -n "UNKNOWN\|NO LICENCE FILE\|UNRESOLVED" "$tmp" >&2
    exit 1
fi

mv "$tmp" "$out"
echo "wrote $out ($(grep -c '^| `' "$out") modules)"
