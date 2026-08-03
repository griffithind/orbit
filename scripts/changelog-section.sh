#!/bin/sh
# Print CHANGELOG.md's section for a version.
#
#   scripts/changelog-section.sh 0.2.0
#
# Sections are "## v<version>" and run until the next "## " at the same level.
# Exits non-zero with nothing on stdout when the section is missing or empty,
# which is what lets the release workflow refuse to publish notes it does not
# have rather than publishing install instructions and calling that a changelog.
set -eu

version="${1:?usage: changelog-section.sh <version>}"
cd "$(dirname "$0")/.."

section=$(awk -v want="## v$version" '
    $0 == want          { grabbing = 1; next }
    grabbing && /^## /  { exit }
    grabbing            { print }
' CHANGELOG.md)

if [ -z "$(printf '%s' "$section" | tr -d '[:space:]')" ]; then
    echo "CHANGELOG.md has no '## v$version' section" >&2
    exit 1
fi

printf '%s\n' "$section"
