# ADR-0018: Windows is a client, and nothing else

**Status:** Accepted
**Date:** 2026-08-12

## Context

`GOOS=windows go vet ./...` passes, and has for as long as the vet loop has existed. That is
the whole of Orbit's Windows story: it compiles. Windows is not in the release matrix
(`release.yml:149`, `Makefile:33` both list only `darwin/{amd64,arm64}` and
`linux/{amd64,arm64}`), so no Windows artifact has ever been produced. There is no
`*_windows.go` file anywhere in `internal/` or `cmd/`.

**Most of a Windows client already exists, in the vendored nebula.** The submodule is pinned at
`v1.11.0-3-g3afbd01` with a single local commit (the darwin `ListenerFactory`), so everything
Windows-related is upstream and unmodified. It builds clean for `windows/{amd64,386,arm64}`,
and upstream runs a real Windows smoke test. What works there: the wintun TUN device with a
deterministic per-name adapter GUID; route installation through the `winipcfg` LUID API rather
than `netsh`; a registered-I/O UDP fast path; Windows Defender Firewall bypass filters via
hand-rolled `fwpuclnt.dll` bindings, on by default; setting the adapter's network category to
Private over COM. Nebula's firewall, lighthouses, relays, handshakes and certificates carry no
build tags at all. The data plane is not the problem.

What Windows lands on in *Orbit's* code is a set of fallbacks that satisfy interfaces and do
nothing: `systemResolvers()` returns `nil`, `applyDNS` returns `ErrDNSUnsupported`, the host
configurer returns `ErrHostStateUnsupported` for any non-empty state, `pinSocket` returns `nil`
silently. Two files are not tagged at all and degrade quietly. `posture.go` reads
`/proc/sys/kernel/osrelease` and `/sys/block`, so every posture signal for a Windows device is
permanently blank even though BitLocker, Secure Boot and TPM are all readable there — and the
blank OS *name* comes from `posture_other.go`, whose `!darwin` tag puts Windows on the Linux
path reading `/etc/os-release`. And `validate.go` never runs `nebula -test` — not because it
looks for `nebula` rather than `nebula.exe`, since Go's `LookPath` appends `PATHEXT` and would
find the `.exe`, but because no `nebula.exe` is shipped in any Orbit artifact. `LookPath`
returns `ErrNotFound`, `Validate` returns `ErrValidationUnavailable`, and by design that must
not block an apply. On Linux an unvalidated apply is an operator omission; on Windows it would
be the shipped default.

Four findings decide the scope.

**There is no service integration.** `PlanService` (`service.go:70-79`) returns an error for
any `GOOS` but linux and darwin. `installCmd` calls it at `agent.go:804`, *before*
`device.LoadOrCreate` at `:821`, so `orbit agent install` fails having written nothing.
`uninstallCmd` calls it at `:876` and returns the error before the directory removal — while
`orbit join` creates the device key without going through `PlanService` at all. A Windows user
can therefore join a network and has no supported way to leave it.

**Exit nodes have no escape from the routing loop, and nebula does not supply one.** On Linux
the outer UDP carries `SO_MARK` and an `ip rule` diverts it; on darwin the socket is bound with
`IP_BOUND_IF`. Neither `listen.so_mark` nor any `IP_UNICAST_IF` equivalent exists in nebula's
Windows path. Meanwhile `overlay/tun_windows.go:215` detects a `0.0.0.0/0` unsafe route and
sets `UseAutomaticMetric = false; Metric = 0` — deliberately making wintun win route
arbitration for everything, nebula's own lighthouse and relay traffic included. Orbit's
`pinSocket` on Windows is a silent no-op, so the agent's escape hatch (ADR-0016) is installed
and pins nothing, with no log line.

**The status socket's security model does not survive the port.** `net.Listen("unix")` works on
Windows 10 1803+ and `os.Stat` reports `ModeSocket` correctly since Go 1.23, so the stale-socket
dance is intact. But `os.Chmod(path, 0o600)` on Windows only clears the read-only attribute, so
the comment at `status.go:50-55` — "0600: root only… on a shared machine that is a map of the
estate" — is false there. Separately, `status.go:477` tests `errors.Is(err,
syscall.ECONNREFUSED)`; on Windows that constant is an invented `APPLICATION_ERROR + iota`
value the OS never returns, so that half of the branch is dead. The `os.ErrNotExist` half on
the same line does work — Go maps `ERROR_FILE_NOT_FOUND` — so what is lost is the *present but
unserved* socket, which is precisely the state `listenUnix`'s stale-socket dance creates.

**Paths are POSIX and signed that way.** `DefaultRoot` is `nebulacfg.AuthoritativeRoot` =
`/var/lib/orbit`, which on Windows becomes `C:\var\lib\orbit`. The control plane renders
config paths with `path.Join` (always `/`) and the agent rewrites them with `filepath.Join`
(`\` on Windows) in `localize`, then `verifyconfig.go` re-runs `localize` and compares
byte-for-byte. It round-trips today, and `internal/agent/paths/contract_test.go:22-47` is the test holding the
two `DirFor` functions to one answer — but it does so by pinning POSIX string literals, so on
Windows it fails rather than proving anything. The round-trip survives because Windows paths
pass through YAML as unquoted plain scalars: it works by luck of quoting rather than by
construction.

## Decision

**Orbit supports Windows as a client: a workstation that joins a mesh and reaches peers.**

In scope: `orbit join`, `orbit agent install/uninstall/run`, `orbit status/peers/why/netcheck`;
a wintun adapter with an overlay address; direct and relayed tunnels, lighthouse registration
and nebula's own firewall; unsafe routes *to* mesh gateways; certificate renewal, generation
apply, the revert guard and config-integrity checking — all of which are platform-independent
today. It runs as a Windows service, survives reboot, keeps state under `%ProgramData%\Orbit`,
and ACLs its key material.

Out of scope, stated in the documentation and enforced by the control plane rather than
discovered by the agent: **serving or consuming an exit route**, **acting as a gateway**
(`orbit.forward`, masquerade, advertised routes), **policy routing**, and **pointing the
machine's own resolver at the mesh**. The control plane refuses to assign an exit node or a
served route to a Windows device, rather than signing a configuration the agent will log an
error about once a minute forever.

Posture is reported as **explicitly unsupported** on Windows rather than silently blank, so a
posture-gated policy fails visibly instead of evaluating a device that can never satisfy it.

The blocking work, in dependency order: SCM integration in `service_windows.go` and the
`PlanService` switch; decoupling `installCmd`/`uninstallCmd` from `PlanService` so join and
uninstall are symmetric; a per-`GOOS` `DefaultRoot` with a round-trip test for
`localize`/`verifyconfig`; adding `windows/amd64` to the release matrix and shipping
`wintun.dll` in `dist\windows\wintun\bin\<arch>\` **next to `orbit.exe`** — because
`checkWinTunExists` resolves it from `os.Executable()`, which under an embedded data plane is
Orbit's binary, not nebula's; real DACLs in place of the `0o600` calls — which are not merely inert: `0600` has `S_IWRITE`
set, so on Windows the call takes the clear-read-only branch and makes the object *more*
accessible, and the same call governs `host.key` (`generation/apply.go:769`) and `device.key`
(`device/identity.go:237`), a strictly worse exposure than the socket; a named pipe with
an Administrators-only SDDL for the status socket, plus the two-line `ECONNREFUSED` fix; an
elevation check whose message says Administrator, not root; and Authenticode signing with an
MSI or winget package.

## Alternatives considered

**Ship the full feature set, including exit nodes and gateways.** Rejected. Closing the exit-node
gap means either upstreaming `IP_UNICAST_IF` socket pinning into nebula's Windows listener —
which the fork's own `ListenerFactory` seam accommodates, so it is the clean path but it is
upstream work — or maintaining dynamic host routes to every peer endpoint, which is a
routing-table race with no owner. A Windows gateway additionally means a full WFP or `netsh`
NAT implementation. Neither is on the path to a client that works, and both would delay it by
months.

**Ship what compiles today and document the gaps.** Rejected. It compiles because every
capability has a no-op fallback, and one of those fallbacks — `pinSocket` — fails *silently*
while the agent believes it has a recovery path. A build that lies about its own safety net is
worse than no build.

**Keep AF_UNIX for the status socket and rely on an ACL'd parent directory.** Cheaper, and it
may work — whether Windows AF_UNIX honours the file DACL on connect is genuinely contested and
we have not measured it. Rejected as the *decision* because the report is a map of the estate
and "we relied on directory ACLs and hoped" is not a security model. If measurement shows the
DACL is honoured, this becomes an implementation shortcut rather than a change of decision.

**Make `AuthoritativeRoot` per-OS on the control plane, so signed configs carry native paths.**
Rejected: it means the control plane learns each device's OS at enrolment and renders
differently per device, multiplying the generation space. `localize` already exists and is
already the single mechanism for platform path divergence; the fix is to make
`nebulacfg`'s `path.Join` and `paths`' `filepath.Join` agree and to test the round-trip, not to
move the divergence upstream.

**Use nebula's own `cmd/nebula-service`.** It exists, it wraps `kardianos/service`, and it
routes logs to the Event Log. Unusable: ADR-0001 has Orbit calling `nebula.Main` in-process, so
nebula's service main is never reached.

## Consequences

Exit nodes are the feature users most expect from a VPN client, and this decision ships a
Windows client without them. That will be the most common complaint, and the honest answer is
that nebula cannot keep its own UDP out of a tunnel it has told Windows to win — which is a
statement about the dependency, not a scheduling excuse.

The control plane acquires per-OS knowledge it does not have today: it must know a device is
Windows to refuse an exit-node assignment. That is a small change and a real coupling, and it
is the first place device platform affects what the control plane will sign.

Windows binaries mean Authenticode signing, which means a certificate, a signing pipeline, and
SmartScreen reputation. Tailscale sidesteps most of the driver-signing burden by shipping
wintun.net's separately-licensed prebuilt DLL, and so do we, via the vendored copy — but our
own binary still needs signing, and that has procurement lead time that nothing else here does.

Windows is already the fourth `GOOS` in ADR-0017's gate loop; what changes is that it becomes a
*release target*, the fifth in a matrix that ships four. That converts "type-checks" into a
claim made to users. The gaps that ADR leaves open — no
execution of platform tests in CI — become materially more expensive the day a Windows artifact
is published. A Windows CI job is not on the blocking list above and should be.

What would trigger revisiting the scope: `IP_UNICAST_IF` landing in nebula's Windows listener.
That single change makes exit-node *consumption* tractable and is the one item that would move
the largest out-of-scope feature back in.

## References

- `internal/agent/service.go:70-79` — `PlanService`'s default branch
- `cmd/orbit/agent.go:804, 821, 876` — install before key, uninstall before removal
- `internal/agent/escapehatch_other.go` — `pinSocket` returning `nil` silently
- `internal/agent/status/status.go:50-55, 477` — the mode comment, and the dead errno branch
- `internal/agent/paths/paths.go:42`, `internal/nebulacfg/render.go:134` — the POSIX root
- `internal/agent/posture/posture.go:94, 115` — the untagged Linux reads
- `third_party/nebula/overlay/tun_windows.go:215, 322-334` — metric 0, and the DLL path
- `third_party/nebula/dist/windows/wintun/bin/` — the vendored, separately-licensed DLL
- ADR-0001 (nebula in-process), ADR-0016 (the exit route fails closed), ADR-0017 (platform gates)
