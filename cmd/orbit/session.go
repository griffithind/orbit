package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/google/uuid"
)

// sessionLs lists live browser sessions.
//
// Live only, which is the difference from `orbit token ls` and is deliberate.
// A revoked token stays listed because "was it used after we revoked it" is the
// question an incident asks and a vanished row cannot answer. A dead session
// answers nothing: it holds no permission, cannot make a request, and its row
// is swept within twelve hours. The question here is what can reach the control
// plane at this moment. The history — who signed in, from where — is in
// `orbit audit -action session.created`, which outlives these rows.
func sessionLs(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("session ls", flag.ContinueOnError)
	var o options
	o.bind(fs)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if err := o.load(); err != nil {
		return err
	}

	res, err := o.client.ListSessions(ctx)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	// BROWSER is the elastic column. It is the only unbounded field here and the
	// only one an operator recognises from a prefix — two sessions on one token
	// from one office address are told apart by this string and by nothing else
	// on the row.
	t := newTable(o.r,
		column{name: "TOKEN"},
		column{name: "ACCESS"},
		column{name: "LAST SEEN"},
		column{name: "FROM"},
		column{name: "BROWSER", elastic: true},
		column{name: "EXPIRES", optional: true},
		column{name: "ID", optional: true},
	)
	for _, sess := range res.Value {
		// "full" rather than "read-write": a full session carries the token's
		// scopes, whatever those are, and calling it read-write would claim it
		// can write things a read-only token never could.
		access := "full"
		if sess.ReadOnly {
			access = "read-only"
		}
		from := sess.CreatedIP
		if from == "" {
			from = "-"
		}
		browser := sess.UserAgent
		if browser == "" {
			browser = "-"
		}
		last := sess.LastSeenAt
		t.add(sess.TokenName, access, ago(&last), from, browser,
			until(sess.ExpiresAt), sess.ID)
	}
	if t.empty() {
		// Not an error, and worth saying plainly: nobody is signed in to the
		// console. The CLI authenticates with a bearer token and opens no
		// session, so this is the expected reading on a deployment where the UI
		// is off or unused.
		fmt.Fprintln(errOut, "no live browser sessions")
		return nil
	}
	t.render(out)
	return nil
}

// sessionRevoke signs one browser out.
//
// No confirmation prompt, matching `orbit membership block` rather than `orbit host
// rm`. The cost of being wrong is one sign-in, and confirm's own doc says why
// that matters: a prompt on something cheap teaches people to type y without
// reading, which is what makes the prompt on an irreversible action worthless.
func sessionRevoke(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("session revoke", flag.ContinueOnError)
	var o options
	o.bind(fs)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit session revoke <uuid>")
	}
	if err := o.load(); err != nil {
		return err
	}

	// By uuid only. A session has no name; the closest thing to one is the
	// token it references, and that is shared by every session it opened —
	// resolving by it would mean guessing which browser to close.
	sessionID, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		return usageErrorf("session revoke takes a uuid. Find it with `orbit session ls` (%v)", err)
	}

	o.announce(fmt.Sprintf("Signing out session %s", sessionID))

	if err := o.client.RevokeSession(ctx, sessionID); err != nil {
		return err
	}
	fmt.Fprintf(out, "signed out %s\n", sessionID)
	fmt.Fprintln(errOut,
		"\nThe token that session used still works. If the CREDENTIAL is what leaked,\n"+
			"revoke the token itself — that also closes every other browser holding it:\n"+
			"\n  orbit token revoke <token-uuid>")
	return nil
}
