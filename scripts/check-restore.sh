#!/bin/sh
# Restore this deployment's backup into a scratch database and prove it opens.
#
# Run this quarterly, alongside check-break-glass. The reasoning is the same and
# ADR-0007 already committed to it: an untested recovery path is a belief, not a
# capability. It is worse here than for the token, because the failures are not
# "it stopped working" — they are things that were never going to work, and
# every one of them was found by reading rather than by trying:
#
#   * The KEK passphrase is the only unrecoverable item. If the deployment
#     raised ORBIT_KEK_ARGON_MEMORY_MIB, the parameter is NOT stored beside the
#     salt, so a restore that forgets it is indistinguishable from a wrong
#     passphrase — which is the one event nothing recovers from.
#   * The replica's membership is found by overlay address and refused if the
#     name differs, and the default name is derived from the hostname. A restore
#     onto a new machine therefore needs `orbitd serve -name <old>`.
#   * `-lighthouse` seeds public addresses only at CREATION, so a restore onto a
#     new public IP keeps advertising the old one to the whole fleet.
#
# This checks the first of those, which is the one a script can check: the dump
# restores, the schema matches this binary, and the vault opens with the
# passphrase and Argon parameters you have. The other two are procedure and are
# in docs/deployment.md section 7.
#
#   ORBIT_DSN=postgres://... ORBIT_KEK_PASSPHRASE_FILE=./kek.pass make check-restore
#
# NOTHING IS WRITTEN TO THE LIVE DATABASE. The scratch database is created and
# dropped by this script; the source is only ever read.
#
# POSIX sh, pg_dump, psql and the orbitd binary. This has to run on a machine
# that may be having a bad day.

set -eu

DSN="${ORBIT_DSN:-}"
ORBITD="${ORBITD:-orbitd}"
SCRATCH="${ORBIT_RESTORE_DB:-orbit_restore_check}"

if [ -z "$DSN" ]; then
    echo "check-restore: set ORBIT_DSN to the ADMIN connection string" >&2
    echo >&2
    echo "  The admin one, not orbit_app's: restoring creates a schema, and the" >&2
    echo "  application role deliberately cannot." >&2
    exit 2
fi
if [ -z "${ORBIT_KEK_PASSPHRASE:-}${ORBIT_KEK_PASSPHRASE_FILE:-}" ]; then
    echo "check-restore: set ORBIT_KEK_PASSPHRASE_FILE (or ORBIT_KEK_PASSPHRASE)" >&2
    echo >&2
    echo "  A restore that cannot open the vault is not a restore. This is the" >&2
    echo "  half of the backup that is not in the dump, and the half whose loss" >&2
    echo "  nothing recovers from." >&2
    exit 2
fi
for tool in pg_dump psql; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "check-restore: $tool is not on PATH" >&2
        exit 2
    }
done

# Everything after the last '/' is the database name; swap it for the scratch
# one and keep the rest — host, port, credentials, sslmode.
base="${DSN%/*}"
query=""
case "$DSN" in *\?*) query="?${DSN#*\?}" ;; esac
scratch_dsn="${base}/${SCRATCH}${query}"
admin_dsn="${base}/postgres${query}"

cleanup() {
    psql "$admin_dsn" -q -c "DROP DATABASE IF EXISTS \"$SCRATCH\"" >/dev/null 2>&1 || true
    rm -f "$dump" 2>/dev/null || true
}
dump=$(mktemp)
trap cleanup EXIT INT TERM

echo "check-restore: dumping (read-only) …"
pg_dump "$DSN" > "$dump"

echo "check-restore: restoring into $SCRATCH …"
psql "$admin_dsn" -q -c "DROP DATABASE IF EXISTS \"$SCRATCH\"" >/dev/null
psql "$admin_dsn" -q -c "CREATE DATABASE \"$SCRATCH\"" >/dev/null
psql "$scratch_dsn" -q -v ON_ERROR_STOP=1 -f "$dump" >/dev/null

# The schema this binary expects, compared by name — the same check serve makes
# before it will start (ADR-0026). A restore that produces a database this
# build refuses to serve is a restore that has not worked.
echo "check-restore: checking the schema and opening the vault …"
if ! "$ORBITD" doctor -dsn "$scratch_dsn" 2>&1 | tee /dev/stderr | grep -q '^ok   migrations'; then
    echo >&2
    echo "check-restore: the restored schema does not match this orbitd." >&2
    exit 1
fi

# And the vault, which is the part that is not in the dump. doctor derives the
# KEK from the passphrase and Argon parameters in THIS environment and checks it
# against the verifier in the restored database — which is exactly the pairing a
# real restore depends on.
if ! "$ORBITD" doctor -dsn "$scratch_dsn" 2>&1 | grep -q '^ok   vault'; then
    echo >&2
    echo "check-restore: the vault did not open against the restored database." >&2
    echo >&2
    echo "  Either the passphrase is wrong, or ORBIT_KEK_ARGON_MEMORY_MIB differs" >&2
    echo "  from the value this deployment was bootstrapped with. Those two are" >&2
    echo "  INDISTINGUISHABLE here, which is why the parameter belongs in the" >&2
    echo "  backup beside the passphrase. See docs/deployment.md section 7." >&2
    exit 1
fi

echo
echo "check-restore: the dump restores, the schema matches, and the vault opens."
echo
echo "Not checked here, and still procedure — see docs/deployment.md section 7:"
echo "  * restoring onto a host with a different hostname needs 'orbitd serve -name'"
echo "  * restoring onto a different public IP needs 'orbit device set-addrs'"
