# The control plane, as one image.
#
# This exists because deploying orbitd to a bare host means Postgres, pg_hba,
# firewalld, systemd units, SELinux, sudo's secure_path, and the CA key's file
# mode — and a real deployment tripped on five of those before it reached
# anything Orbit does. None of them exist here.
#
# Build:  docker build -t orbit:dev .
# Run:    docker compose up -d

FROM golang:1.26-alpine AS build

# Layer the module download separately so a source change does not refetch the
# dependency graph. gvisor and nebula are most of it.
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# VERSION is stamped the same way the release workflow stamps it. Unset means
# "dev", which is always visible and never a release — an empty string would
# vanish behind an omitempty tag and make a failed injection look like an old
# build.
ARG VERSION=dev
# An empty directory to copy in with the right ownership below. distroless has
# no shell, so there is no mkdir in the final stage.
RUN mkdir -p /out/state && \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false \
        -ldflags "-s -w -X github.com/griffithind/orbit/internal/version.Version=${VERSION}" \
        -o /out/orbitd ./cmd/orbitd && \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false \
        -ldflags "-s -w -X github.com/griffithind/orbit/internal/version.Version=${VERSION}" \
        -o /out/orbit ./cmd/orbit

# Distroless rather than alpine: orbitd is statically linked and needs no shell,
# no package manager, and no libc. What a shell buys an operator here is the
# ability to poke at the machine holding the mesh's root CA key.
#
# `docker compose exec` still works for orbitd's own subcommands — bootstrap,
# migrate, token — because those are the binary, not a shell.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/orbitd /usr/local/bin/orbitd
COPY --from=build /out/orbit  /usr/local/bin/orbit

# Where the CA key lives, owned by the user that runs. Mount a volume here;
# losing it means every host re-enrolls by hand.
COPY --from=build --chown=nonroot:nonroot /out/state /var/lib/orbit
VOLUME /var/lib/orbit

# WORKDIR, and it is load-bearing rather than tidy.
#
# `orbitd bootstrap` defaults -ca-key to the RELATIVE path ca.key. Without this
# that resolved to /home/nonroot inside the container, so
# `docker compose run --rm orbitd bootstrap` wrote the mesh's root CA key into a
# container that was then deleted — and the failure is silent until the first
# certificate renewal, at which point nothing can issue one and every host has
# to re-enrol by hand. Resolving it inside the volume makes the default correct.
WORKDIR /var/lib/orbit

# nonroot (uid 65532). orbitd needs no privileged port and no tun device — it
# joins the overlay on a userspace network stack — so there is nothing here that
# wants root, and the process holding the CA signing key should have as little
# of the machine as it can work with.
USER nonroot:nonroot

EXPOSE 8080/tcp 4242/udp

ENTRYPOINT ["/usr/local/bin/orbitd"]
CMD ["serve"]
