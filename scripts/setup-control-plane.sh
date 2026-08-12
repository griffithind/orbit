#!/usr/bin/env bash
# Set up an Orbit control plane on a fresh RHEL-family host, as containers.
#
#   curl -fsSL https://raw.githubusercontent.com/griffithind/orbit/main/scripts/setup-control-plane.sh \
#       | sudo bash -s -- --public-ip 203.0.113.10
#
# It installs docker, opens two ports, generates every secret, migrates the
# database, bootstraps the network, and starts the control plane. It prints an
# admin token once and tells you what to do next.
#
# SAFE TO RE-RUN. Secrets already in .env are reused rather than regenerated —
# regenerating the database password after the role exists would lock the
# control plane out of its own data — and a network that has already been
# bootstrapped is not bootstrapped again.
#
# It does NOT put TLS in front of the enrollment endpoint. Enrollment codes are
# single-use with a 15-minute TTL, so the exposure is bounded, but it is real:
# see the closing notes.
set -euo pipefail

# EVERY `docker compose run` IN THIS SCRIPT MUST REDIRECT STDIN FROM /dev/null.
#
# The supported way to run this is `curl ... | sudo bash`, which puts the
# SCRIPT ITSELF on stdin. `docker compose run` attaches stdin to the container
# and consumes it — so it eats the rest of the script, bash reaches EOF, and the
# run stops silently having done only the steps above the first such command.
#
# It exits 0 while doing so, which is the worst part: the database gets migrated
# and nothing after that happens, so the operator is left with a healthy
# Postgres, no network id, no admin token and no control plane — and no error to
# search for. -T is not enough; it only disables TTY allocation.

REPO_URL=${ORBIT_REPO_URL:-https://github.com/griffithind/orbit}
# Resolved from the API, not pinned. A hardcoded default goes stale at every
# release and installs an old control plane on a fresh machine — silently, since
# nothing about the run looks wrong. --version pins it deliberately.
VERSION=${ORBIT_VERSION:-}
DIR=${ORBIT_DIR:-/opt/orbit}
NETWORK=prod
CIDR=10.42.0.0/16
CERT_TTL=168h
OVERLAY_ADDR=10.42.0.1
PUBLIC_IP=""
ENROLL_URL=""

die() { echo "setup: $*" >&2; exit 1; }
say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
    cat <<EOF

Options:
  --public-ip <addr>    this machine's public address (required)
  --network <name>      network name, default $NETWORK
  --cidr <prefix>       overlay prefix, default $CIDR
  --overlay-addr <addr> the control plane's own overlay address, default $OVERLAY_ADDR
  --cert-ttl <dur>      host certificate lifetime, default $CERT_TTL
  --enroll-url <url>    what agents enroll against, default http://<public-ip>:8080/enroll/v1/enroll
  --version <x.y.z>     Orbit version; the latest release when unset
  --dir <path>          where to check the repository out, default $DIR
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --public-ip)    PUBLIC_IP=$2; shift 2 ;;
        --network)      NETWORK=$2; shift 2 ;;
        --cidr)         CIDR=$2; shift 2 ;;
        --overlay-addr) OVERLAY_ADDR=$2; shift 2 ;;
        --cert-ttl)     CERT_TTL=$2; shift 2 ;;
        --enroll-url)   ENROLL_URL=$2; shift 2 ;;
        --version)      VERSION=$2; shift 2 ;;
        --dir)          DIR=$2; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[ "$(id -u)" = 0 ] || die "run as root (sudo)"
[ -n "$PUBLIC_IP" ] || { usage >&2; die "--public-ip is required

It is the address every managed host is told to find this machine at. It
cannot be discovered from behind NAT, which is why you state it — and a
lighthouse nobody can reach is worse than none, because every host keeps
dialling it."; }
command -v dnf >/dev/null 2>&1 || die "this expects a RHEL-family host (dnf)"

[ -n "$ENROLL_URL" ] || ENROLL_URL="http://${PUBLIC_IP}:8080/enroll/v1/enroll"

#------------------------------------------------------------------------------
say "Packages"

dnf -y install git firewalld >/dev/null
if ! command -v docker >/dev/null 2>&1; then
    dnf -y config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo >/dev/null
    dnf -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null
fi
systemctl enable --now docker >/dev/null
docker compose version >/dev/null 2>&1 || die "docker compose v2 is not available"
echo "docker $(docker --version | awk '{print $3}' | tr -d ,)"

#------------------------------------------------------------------------------
say "Firewall"

systemctl enable --now firewalld >/dev/null
# A RANGE, not a single port, and the reason is structural rather than a
# convenience. Nebula's wire header carries no network identifier, so one UDP
# socket serves exactly one network and a control plane on N networks binds N
# ports. Opening the range once, at install, is what stops adding a second
# network from being a firewall change on a machine you may not be sitting at.
#
# 4242-4257 is sixteen. 4242 stays the first, so a single-network deployment is
# unchanged; sixteen covers what a self-hosted control plane plausibly runs
# (prod, staging, dev, a few per-tenant) while staying small enough to be one
# rule rather than a wildcard. Past that, run a second instance over a disjoint
# set of networks.
#
# Opening a port is not listening on it: only networks actually passed to --mesh
# bind anything, and the rest refuse at the socket layer whatever the firewall
# says.
firewall-cmd --permanent --add-port=4242-4257/udp >/dev/null
firewall-cmd --permanent --add-port=8080/tcp >/dev/null
firewall-cmd --reload >/dev/null
# 8443 is deliberately absent: the agent API listens on orbitd's in-process
# userspace stack, so the kernel never binds it and there is nothing to open.
echo "4242-4257/udp and 8080/tcp open; ssh untouched"
firewall-cmd --list-services | tr ' ' '\n' | grep -qx ssh \
    || echo "WARNING: ssh is not in the firewall's service list — check before you log out" >&2

#------------------------------------------------------------------------------
say "Source"

# Resolved through the API rather than the /latest/download redirect, so the
# version is known before anything is checked out and the SAME version ends up
# in .env, in the image tag, and in the tag we check out. scripts/install.sh
# resolves it identically; the two must not drift.
if [ -z "$VERSION" ]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/griffithind/orbit/releases/latest" |
        sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)
    [ -n "$VERSION" ] || die "could not determine the latest version; pass --version"
    echo "latest release is v$VERSION"
fi

if [ -d "$DIR/.git" ]; then
    git -C "$DIR" fetch --tags --quiet
else
    git clone --quiet "$REPO_URL" "$DIR"
fi
git -C "$DIR" checkout --quiet "v$VERSION" 2>/dev/null \
    || die "no tag v$VERSION in $REPO_URL"

# Nebula is a submodule, and go.mod's replace points the build at it. Neither
# clone nor checkout brings it, so without this the image build fails on a
# missing file in third_party/nebula — and only on the fallback path, which is
# the one taken exactly when the published image could not be pulled. Two things
# have to go wrong before anyone sees it, which is why it survived a release.
#
# Recursive and after every checkout, not just the clone: a re-run that moves to
# a new version moves the pointer with it.
git -C "$DIR" submodule update --init --recursive --quiet \
    || die "could not fetch the nebula submodule in $DIR"

cd "$DIR/deploy"
echo "orbit v$VERSION at $DIR"

#------------------------------------------------------------------------------
say "Secrets"

# SECRETS are generated once and never regenerated: rotating
# POSTGRES_APP_PASSWORD here would leave the database expecting the old one and
# the control plane unable to connect, with nothing saying why.
#
# ADDRESSES are the opposite, and conflating the two cost a real deployment an
# hour. A first run with the wrong --public-ip — the example address from the
# usage text, say — wrote it into .env, and every re-run reused it however many
# times the correct one was passed. The control plane then advertises a
# lighthouse nobody can reach, hosts enroll fine and never complete a handshake,
# and nothing in the output says the address is wrong.
#
# So: what is passed on the command line wins, every time.
if [ -f .env ]; then
    echo "reusing the secrets in .env"
    ADDR_CHANGED=0
    for kv in "ORBIT_PUBLIC_ADDR=${PUBLIC_IP}:4242" \
              "ORBIT_ENROLL_URL=$ENROLL_URL" \
              "ORBIT_OVERLAY_ADDR=$OVERLAY_ADDR" \
              "ORBIT_VERSION=$VERSION"; do
        key=${kv%%=*}
        old=$(sed -n "s|^$key=||p" .env | head -1)
        if [ "$old" != "${kv#*=}" ]; then
            echo "  $key: ${old:-<unset>} -> ${kv#*=}"
            if [ "$key" = ORBIT_PUBLIC_ADDR ]; then ADDR_CHANGED=1; fi
        fi
        if grep -q "^$key=" .env; then
            sed -i "s|^$key=.*|$kv|" .env
        else
            printf '%s\n' "$kv" >> .env
        fi
    done
else
    umask 077
    cat > .env <<EOF
# Generated by scripts/setup-control-plane.sh. Secrets: keep this 0600.
POSTGRES_SUPERUSER_PASSWORD=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')
POSTGRES_APP_PASSWORD=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')
ORBIT_PUBLIC_ADDR=${PUBLIC_IP}:4242
ORBIT_ENROLL_URL=$ENROLL_URL
ORBIT_OVERLAY_ADDR=$OVERLAY_ADDR
ORBIT_VERSION=$VERSION
ORBIT_NETWORK=
EOF
    echo "wrote .env"
fi
chmod 0600 .env

# The KEK passphrase is written SEPARATELY, and that is the point of it.
#
# It used to be a line in .env, next to the database passwords, in the directory
# that also carries the database volume. So the default state on disk was a
# backup and the key that opens it, together — the one arrangement envelope
# encryption exists to rule out. Anyone who tarred this directory took both.
#
# A file also lets compose pass ORBIT_KEK_PASSPHRASE_FILE instead of an
# environment variable, which keeps it out of `docker inspect`.
if [ ! -f kek.pass ]; then
    umask 077
    head -c 32 /dev/urandom | base64 > kek.pass
    echo "wrote kek.pass"
fi
chmod 0600 kek.pass

# There was a second secret here, ./ca-pass, passed as
# ORBIT_CA_KEY_PASSPHRASE_FILE. It never did anything. That variable is a
# compatibility ALIAS for the KEK, read only when ORBIT_KEK_PASSPHRASE is unset,
# from before the CA key moved into Postgres — so the deployment protected two
# secrets where one was real, and would have fallen back to the wrong one, and
# failed to decrypt anything, if the KEK variable were ever empty. One secret,
# in .env.

set -a
# shellcheck disable=SC1091
. ./.env
set +a

# Correcting .env is only half of a changed public address.
#
# --lighthouse is a SEED: it applies when the control plane's host record is
# first created, and after that the record is the source of truth — exactly as
# it is for every other host. So a corrected address in .env reaches nebula's
# own config and NOT the address this control plane advertises to agents, and
# hosts go on dialling somewhere nothing answers. They enroll fine and never
# complete a handshake, which looks like a firewall problem and is not.
if [ "${ADDR_CHANGED:-0}" = 1 ] && [ -n "${ORBIT_NETWORK:-}" ]; then
    cat >&2 <<EOF

WARNING: the public address changed on a network that is already bootstrapped.

.env is updated, but the control plane's HOST RECORD still advertises the old
one, and that record — not this file — is what agents are told to dial. Fix it
with an admin token:

  docker compose run --rm -e ORBIT_TOKEN=<token> orbit membership ls
  docker compose run --rm -e ORBIT_TOKEN=<token> \
      orbit device set-addrs <control-plane-name> ${PUBLIC_IP}

Machines that already joined against the old address cannot receive that
correction over an overlay they never reached; re-run 'orbit join' on
them, which is idempotent and returns the membership they already hold.

EOF
fi

#------------------------------------------------------------------------------
say "Image"

# The publish job is newer than the compose file that pulls from it, so a
# missing image is a plausible state rather than an impossible one. Building
# locally is a complete substitute — the Dockerfile is multi-stage and needs
# nothing but docker.
if docker pull --quiet "ghcr.io/griffithind/orbit:$VERSION" >/dev/null 2>&1; then
    echo "pulled ghcr.io/griffithind/orbit:$VERSION"
else
    echo "no published image for $VERSION (or the registry refused); building locally"
    docker compose build --quiet orbitd
fi

#------------------------------------------------------------------------------
say "Database"

docker compose run --rm -T orbitd migrate --app-password "$POSTGRES_APP_PASSWORD" < /dev/null

#------------------------------------------------------------------------------
say "Bootstrap"

ADMIN_TOKEN=""
BREAK_GLASS=""
FRESH=0

if [ -n "${ORBIT_NETWORK:-}" ]; then
    echo "already bootstrapped as $ORBIT_NETWORK; skipping"
else
    FRESH=1
    # Captured as well as shown, because the network id has to be written back
    # into .env and the admin token is printed exactly once. 0600 and named so
    # it is obvious what it holds.
    #
    # -T disables compose's pseudo-TTY. With a TTY allocated the container's
    # output does not reliably reach a pipe, which is how a run can complete
    # successfully and hand back no token at all.
    out=bootstrap-output.txt
    umask 077
    docker compose run --rm -T orbitd bootstrap \
        --network "$NETWORK" --cidr "$CIDR" --cert-ttl "$CERT_TTL" < /dev/null | tee "$out"
    chmod 0600 "$out"

    net=$(sed -n 's/^ *export ORBIT_NETWORK=//p' "$out" | tr -d '\r' | head -1)
    [ -n "$net" ] || die "could not read the network id from bootstrap output ($out)"
    sed -i "s|^ORBIT_NETWORK=.*|ORBIT_NETWORK=$net|" .env
    export ORBIT_NETWORK=$net
    echo "network $net written to .env"

    ADMIN_TOKEN=$(sed -n 's/^ *export ORBIT_TOKEN=//p' "$out" | tr -d '\r' | head -1)
    [ -n "$ADMIN_TOKEN" ] || die "bootstrap did not yield an admin token ($out).
Mint one with:  docker compose run --rm -T orbitd token create --name admin --scopes '*'"
fi

#------------------------------------------------------------------------------
say "Start"

docker compose up -d
for i in $(seq 1 60); do
    if curl -fsS localhost:8080/readyz >/dev/null 2>&1; then
        echo "ready after ${i}s"
        break
    fi
    [ "$i" = 60 ] && {
        docker compose logs --tail=40 orbitd >&2
        die "the control plane did not become ready; logs above"
    }
    sleep 1
done

#------------------------------------------------------------------------------
say "Break-glass token"

# Minted now, while everything works. POST /v1/tokens needs a token, so the one
# failure the API cannot help with is losing every admin credential.
#
# Only on a fresh bootstrap: minting one on every re-run would leave a trail of
# "*" tokens nobody is tracking, which is the opposite of what this is for.
if [ "$FRESH" = 1 ]; then
    BREAK_GLASS=$(docker compose run --rm -T orbitd token create < /dev/null \
        --name break-glass --scopes '*' 2>/dev/null | tr -d '\r' | tail -1)
    printf 'break-glass %s\n' "$BREAK_GLASS" >> bootstrap-output.txt
    chmod 0600 bootstrap-output.txt
    echo "minted"
else
    echo "skipped on a re-run; mint one with:"
    echo "  docker compose run --rm -T orbitd token create --name break-glass --scopes '*'"
fi

#------------------------------------------------------------------------------
cat <<EOF

$(printf '\033[1m')Done.$(printf '\033[0m')  The control plane is running and is its own lighthouse.

  network      $ORBIT_NETWORK
  enroll at    $ENROLL_URL
  lighthouse   ${PUBLIC_IP}:4242
  overlay      $OVERLAY_ADDR

EOF

# The tokens, printed HERE rather than only where they were generated.
#
# Both scroll past behind compose's progress output, `up -d`, and the readiness
# loop — and the admin token is shown exactly once by bootstrap, so a run that
# completes and leaves an operator without it has failed at the only thing it
# could not redo.
if [ "$FRESH" = 1 ]; then
    printf '\033[1m%s\033[0m\n' "Admin token — shown once, store it now:"
    printf '\n  %s\n\n' "$ADMIN_TOKEN"
    printf '\033[1m%s\033[0m\n' "Break-glass token — store this somewhere else entirely:"
    printf '\n  %s\n\n' "$BREAK_GLASS"
    cat <<EOF
Both are also in $PWD/bootstrap-output.txt (0600, gitignored).
Once they are somewhere safe:  shred -u bootstrap-output.txt

EOF
else
    cat <<EOF
This network was already bootstrapped, so no admin token was issued — bootstrap
prints one exactly once. If you no longer have it:

  docker compose run --rm -T orbitd token create --name admin --scopes '*'

EOF
fi

cat <<EOF

Add a machine. Reserve a place for it, which prints a single-use code:

  cd $PWD
  docker compose run --rm -e ORBIT_TOKEN=<admin token> \
      orbit membership reserve --name macbook --role default

(or put ORBIT_TOKEN in .env and drop the -e). From your laptop instead:

  export ORBIT_URL=http://${PUBLIC_IP}:8080
  export ORBIT_TOKEN=<the admin token>
  export ORBIT_NETWORK=$NETWORK
  orbit membership reserve --name macbook --role default

Then on the machine joining, with the code that printed:

  sudo orbit agent install
  sudo orbit join --url http://${PUBLIC_IP}:8080 --network $NETWORK --code orb_1_...

An overlay address is allocated when the machine arrives; --addr pins one if
something outside Orbit already refers to it.

--role default matters: a membership with no role gets outbound-only, so nothing
can reach it, not even ICMP.

No code, no reservation: drop the --code and the machine waits in
'orbit membership pending' for you to authorize it. Better for a laptop you hand
to somebody, because no secret has to travel.

'install' is once per machine — it generates the device identity and the
service. 'join' is once per network, and the service picks each one up without
a restart.

Verify on that host with 'orbit status' — a recent successful poll IS the proof,
because that request crossed the overlay to $OVERLAY_ADDR:8443. Do not test with
'ping $OVERLAY_ADDR': the control plane accepts exactly one inbound port, the
agent API, so it will not answer ICMP by design.

Back up TWO things, and keep them apart. The CA key and the network identity
key are rows in Postgres, encrypted under the KEK — so a backup is the database
AND the passphrase, and either alone is worthless.

(The full backup set, including the device key and the Argon parameter, is one
table in docs/deployment.md section 7. These are the two that cannot be
reconstructed from anything.)

  docker compose exec -T postgres pg_dump -U postgres orbit | gzip > orbit-db.sql.gz
  cat kek.pass                              # store this somewhere else entirely

The passphrase is in its own file, not in .env, precisely so that "somewhere
else" is possible: .env sits in this directory, and so does the database volume,
so a passphrase kept there travels with every backup of the thing it protects.

That separation is the design: a leaked dump cannot mint a certificate. It also
means losing the passphrase destroys the network exactly as losing the database
does — nebula has no intermediate CAs, so every host re-enrolls by hand.

Enrollment is over plain HTTP. Codes are single-use and expire in 15 minutes,
but they do cross the wire in the clear — put TLS in front of :8080 and re-run
with --enroll-url https://<name>/enroll/v1/enroll before this is real.
EOF
