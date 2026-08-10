#!/bin/sh
# Install orbit, and orbitd if this machine is the control plane.
#
#   curl -fsSL https://raw.githubusercontent.com/griffithind/orbit/main/scripts/install.sh | sh
#   curl -fsSL … | sh -s -- --version 0.3.0 --control-plane
#
# It detects the platform, downloads from the GitHub release, VERIFIES against
# SHA256SUMS, and installs to /usr/local/bin. It enrolls nothing and starts
# nothing: `orbit agent install` and `orbitd bootstrap` are the steps that
# change a machine, and they should be run deliberately rather than by a pipe.
set -eu

REPO=${ORBIT_REPO:-griffithind/orbit}
VERSION=${ORBIT_VERSION:-}
PREFIX=${ORBIT_PREFIX:-/usr/local/bin}
CONTROL_PLANE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION=$2; shift 2 ;;
        --prefix)  PREFIX=$2;  shift 2 ;;
        --control-plane) CONTROL_PLANE=1; shift ;;
        -h|--help)
            sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

fail() { echo "install: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required"; }

need curl
need tar

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) fail "unsupported architecture: $ARCH" ;;
esac
case "$OS" in
    linux|darwin) ;;
    *) fail "unsupported OS: $OS" ;;
esac

# orbitd is Linux only. Asking for it on macOS is a mistake worth naming rather
# than a 404 from the download.
if [ "$CONTROL_PLANE" = 1 ] && [ "$OS" != linux ]; then
    fail "the control plane is Linux only; orbitd is not published for $OS"
fi

# Resolve "latest" through the API rather than the /latest/download redirect,
# because every artifact name carries its version and the redirect does not tell
# us which one it landed on.
if [ -z "$VERSION" ]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
        sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)
    [ -n "$VERSION" ] || fail "could not determine the latest version; pass --version"
fi

BASE="https://github.com/$REPO/releases/download/v$VERSION"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

echo "orbit $VERSION for $OS/$ARCH"

BINARIES="orbit"
[ "$CONTROL_PLANE" = 1 ] && BINARIES="orbit orbitd"

for b in $BINARIES; do
    f="${b}_${VERSION}_${OS}_${ARCH}.tar.gz"
    curl -fsSLO "$BASE/$f" || fail "download $f"
done
curl -fsSLO "$BASE/SHA256SUMS" || fail "download SHA256SUMS"

# Verified before anything is unpacked, and a missing checksum tool is a refusal
# rather than a warning: an unverified binary that manages a mesh's identities
# is not an acceptable degraded mode.
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c SHA256SUMS --ignore-missing >/dev/null || fail "checksum mismatch"
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c SHA256SUMS --ignore-missing >/dev/null || fail "checksum mismatch"
else
    fail "neither sha256sum nor shasum is available; cannot verify the download"
fi
echo "checksums ok"

for b in $BINARIES; do
    tar -xzf "${b}_${VERSION}_${OS}_${ARCH}.tar.gz" "$b"
done

# sudo only if it is needed. Piping a script into a root shell is a habit worth
# not teaching, and most of this does not require it.
SUDO=""
if [ ! -w "$PREFIX" ]; then
    command -v sudo >/dev/null 2>&1 || fail "$PREFIX is not writable and sudo is unavailable"
    SUDO=sudo
fi

for b in $BINARIES; do
    $SUDO install -m 0755 "$b" "$PREFIX/$b"
    echo "installed $PREFIX/$b"
done

echo
"$PREFIX/orbit" version >/dev/null || fail "the installed binary does not run"

if [ "$CONTROL_PLANE" = 1 ]; then
    cat <<EOF
Next, on this machine:

  orbitd migrate -dsn "postgres://postgres@localhost/orbit" -app-password '<secret>'
  orbitd bootstrap -dsn "\$ORBIT_DSN" -network prod -cidr 10.42.0.0/16 \\
      -write-unit -enroll-url https://<public>/enroll/v1/enroll \\
      -overlay-addr 10.42.0.1 -lighthouse <public>:4242

bootstrap prints an admin token once, and -write-unit leaves a unit ready to
enable.
EOF
else
    cat <<EOF
Next, on this host:

  sudo orbit agent install
sudo orbit join -url https://<control-plane> -network prod

That generates this machine's device identity, asks to join, and waits for an
operator to authorize it with 'orbit membership authorize <id>'.

To skip the wait, have someone with an admin token reserve a place first —
'orbit membership reserve -name <name>' prints a single-use code — and pass it:

  sudo orbit join -url https://<control-plane> -network prod -code orb_1_…
EOF
fi
