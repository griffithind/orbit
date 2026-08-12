package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/griffithind/orbit/internal/db"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/web"
)

// `orbitd doctor` — everything serve checks, before serve starts checking it.
//
// serve validates as it goes: the DSN when it opens the pool, the KEK when it
// unseals the vault, the mesh ports when it joins, and -addr at the very last
// statement, after the store is open, the CA registry is built and every mesh
// node has joined. A typo'd listen address therefore costs a full startup and
// fails on the last line, which is the shape of a bad deployment experience
// rather than a bug — but it is still one somebody hits at three in the morning.
//
// Every check here is read-only and every one of them is a failure serve would
// have found eventually. Ordered cheapest first, so the common mistakes are
// reported before the expensive ones are attempted.

type check struct {
	name   string
	ok     bool
	detail string
	advice string
}

func doctorCmd(args []string) error {
	// Its own signal context rather than one threaded from main, matching the
	// other orbitd subcommands: doctor makes network calls with their own
	// timeouts and should stop when the operator gives up on it.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		dsn        = fs.String("dsn", "", "postgres DSN for the orbit_app role (or ORBIT_DSN)")
		addr       = fs.String("addr", ":8080", "listen address serve would bind")
		uiAddr     = fs.String("ui-addr", "", "operator console listen address")
		uiURL      = fs.String("ui-url", "", "public URL the console is reached at")
		enrollURL  = fs.String("enroll-url", "", "public enroll URL handed to agents")
		meshFlag   meshSpecs
		nebulaPort = fs.Int("nebula-port", DefaultNebulaPort, "default nebula UDP port")
		timeout    = fs.Duration("timeout", 5*time.Second, "per-check timeout")
	)
	fs.Var(&meshFlag, "mesh", "network=addr[:port], repeatable — as passed to serve")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *dsn == "" {
		*dsn = os.Getenv("ORBIT_DSN")
	}

	var checks []check
	add := func(c check) { checks = append(checks, c) }

	// Listen addresses first. They cost nothing to test and they are the
	// failures serve discovers last.
	add(bindable("addr", *addr))
	if *uiAddr != "" {
		add(bindable("ui-addr", *uiAddr))
	}
	if len(meshFlag) > 0 {
		if err := checkMeshPorts(meshFlag, *nebulaPort); err != nil {
			add(check{name: "mesh ports", detail: err.Error(),
				advice: "two networks cannot share a UDP port: nebula's v1 header carries " +
					"no network id, so a received packet could not be attributed to one"})
		} else {
			add(check{name: "mesh ports", ok: true,
				detail: fmt.Sprintf("%d network(s), no port collisions", len(meshFlag))})
		}
	}

	if *uiAddr != "" || *uiURL != "" {
		if err := web.CheckExposure(*uiAddr, *uiURL); err != nil {
			add(check{name: "ui exposure", detail: err.Error()})
		} else {
			add(check{name: "ui exposure", ok: true, detail: "console binding and URL agree"})
		}
	}

	// enroll-url is never validated by serve at all: it flows straight into
	// every agent's configuration, so a wrong one is discovered by the fleet.
	add(enrollURLCheck(*enrollURL))

	// Then the database, which is the expensive one.
	if *dsn == "" {
		add(check{name: "database", detail: "no DSN",
			advice: "pass --dsn or set ORBIT_DSN"})
	} else {
		dbCtx, cancel := context.WithTimeout(ctx, *timeout)
		checks = append(checks, databaseChecks(dbCtx, *dsn)...)
		cancel()
	}

	healthy := true
	for _, c := range checks {
		mark := "ok  "
		if !c.ok {
			mark, healthy = "FAIL", false
		}
		fmt.Printf("%-4s %-14s %s\n", mark, c.name, c.detail)
		if c.advice != "" && !c.ok {
			fmt.Printf("     %-14s %s\n", "", c.advice)
		}
	}
	if !healthy {
		return fmt.Errorf("%d of %d checks failed", countFailed(checks), len(checks))
	}
	return nil
}

func countFailed(cs []check) int {
	n := 0
	for _, c := range cs {
		if !c.ok {
			n++
		}
	}
	return n
}

// bindable actually binds and releases, rather than parsing the address.
//
// Parsing catches a malformed address; only binding catches the two that
// actually happen — a port already in use, and an address this host does not
// own.
func bindable(name, addr string) check {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		advice := "another process holds it, or this host does not own that address"
		if strings.Contains(err.Error(), "permission denied") {
			advice = "ports below 1024 need CAP_NET_BIND_SERVICE or root"
		}
		return check{name: name, detail: err.Error(), advice: advice}
	}
	actual := ln.Addr().String()
	_ = ln.Close()
	return check{name: name, ok: true, detail: "can bind " + actual}
}

func enrollURLCheck(raw string) check {
	if raw == "" {
		return check{name: "enroll-url", detail: "not set",
			advice: "serve accepts this empty and hands it to every agent, so the " +
				"fleet finds out instead of you"}
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return check{name: "enroll-url", detail: raw + " has no scheme"}
	}
	if strings.HasPrefix(raw, "http://") {
		return check{name: "enroll-url", ok: true, detail: raw + " (plaintext)",
			advice: ""}
	}
	return check{name: "enroll-url", ok: true, detail: raw}
}

// databaseChecks reports reachability, role and migration state.
//
// Read-only, deliberately: doctor must be safe to run against a production
// control plane while it is serving, so it never applies a migration.
func databaseChecks(ctx context.Context, dsn string) []check {
	st, err := store.Open(ctx, dsn)
	if err != nil {
		return []check{{name: "database", detail: err.Error(),
			advice: "check the DSN, that postgres is up, and that pg_hba admits this host"}}
	}
	defer st.Close()

	out := []check{{name: "database", ok: true, detail: "connected"}}

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return append(out, check{name: "migrations", detail: err.Error()})
	}
	defer conn.Close(ctx)

	drift, err := db.CheckSchema(ctx, conn)
	if err != nil {
		return append(out, check{name: "migrations", detail: err.Error(),
			advice: "the schema is absent or unreadable by this role; run `orbitd migrate`"})
	}
	if drift.OK() {
		out = append(out, check{name: "migrations", ok: true, detail: drift.Reason()})
	} else {
		out = append(out, check{name: "migrations", detail: drift.Reason(),
			advice: "serve refuses to start against a schema it disagrees with"})
	}
	return out
}
