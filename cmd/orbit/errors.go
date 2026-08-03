package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/griffithind/orbit/internal/adminclient"
)

// Exit codes.
//
// These mirror the classes scripts/check-break-glass.sh already distinguishes,
// and they are distinguished for the same reason it distinguishes them: each one
// has a different remedy. A script that only knows "non-zero" retries a revoked
// token against a control plane that is down, and reports neither.
const (
	exitOK           = 0
	exitFailure      = 1 // server 5xx, or something local went wrong
	exitUsage        = 2 // bad flags, bad arguments, a name that resolves to nothing
	exitUnauthorized = 3 // 401
	exitForbidden    = 4 // 403
	exitNotFound     = 5 // 404
	exitConflict     = 6 // 409
	exitUnreachable  = 7 // no answer at all
)

// exitError carries a code the default mapping would not produce, and a message
// already rendered for a human.
//
// Used where the CLI knows more than the status line does — every 409 renderer,
// and the resolution failures that are a typo rather than a server state.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func fail(code int, format string, args ...any) error {
	return &exitError{code: code, msg: fmt.Sprintf(format, args...)}
}

// usageErrorf is exit 2: the command was called wrongly.
func usageErrorf(format string, args ...any) error {
	return &exitError{code: exitUsage, msg: fmt.Sprintf(format, args...)}
}

// exitCode maps an error to a process exit status.
//
// The message the operator sees is produced here too, because for several
// classes the remedy is more useful than the diagnosis and the server cannot
// know it: the server does not know where orbitd runs, and it does not know what
// this CLI is called.
func exitCode(err error) (int, string) {
	if err == nil {
		return exitOK, ""
	}

	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code, ee.msg
	}

	// Resolution failures are decided from a listing this caller could read, so
	// they are a mistyped argument, not a state of the control plane.
	if errors.Is(err, adminclient.ErrNoMatch) || errors.Is(err, adminclient.ErrAmbiguous) {
		return exitUsage, err.Error()
	}

	var unreachable *adminclient.UnreachableError
	if errors.As(err, &unreachable) {
		return exitUnreachable, unreachable.Error() + "\n\n" +
			"This is not an authentication failure: nothing answered. Check that orbitd\n" +
			"is running, that -url (or ORBIT_URL) points at its admin listener, and that\n" +
			"you can route to it."
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return exitUnreachable, err.Error()
	}

	var api *adminclient.APIError
	if errors.As(err, &api) {
		return apiExit(api)
	}
	return exitFailure, err.Error()
}

func apiExit(e *adminclient.APIError) (int, string) {
	switch e.Status {
	case http.StatusUnauthorized:
		// Named precisely, because the three causes are indistinguishable to the
		// server by design and the operator has to consider all of them.
		return exitUnauthorized, "token rejected — revoked, expired, or from a different deployment\n\n" +
			"Mint a replacement ON THE CONTROL PLANE HOST, where the database is reachable:\n\n" +
			"  orbitd token create -name replacement -scopes '*'\n\n" +
			"That path exists precisely because minting a token through the API needs a\n" +
			"token, which is the thing you no longer have."

	case http.StatusForbidden:
		scope := e.MissingScope()
		if scope == "" {
			return exitForbidden, e.Message
		}
		return exitForbidden, fmt.Sprintf(
			"the token authenticated but lacks the scope %q\n\n"+
				"A token that holds tokens:write can grant it:\n\n"+
				"  orbit token create -name <name> -scopes %s\n\n"+
				"This is not the same failure as a rejected token: this credential is valid, "+
				"it is simply narrower than this command.", scope, scope)

	case http.StatusNotFound:
		// Never "or you may not have permission to see it". The API conflates
		// absent and forbidden deliberately, so that a failed lookup cannot
		// confirm that something exists; a CLI that hinted at the distinction
		// would hand a prober exactly what the server withheld.
		return exitNotFound, e.Message

	case http.StatusConflict:
		// Reached only when a command did not render its own 409. Every route
		// that carries a useful body handles it itself; this is the fallback.
		return exitConflict, e.Message

	case http.StatusBadRequest:
		// The server rejected what this invocation asked for, which is an
		// argument problem, and the remedy is on this side of the wire.
		return exitUsage, e.Message

	default:
		if e.Status >= 500 {
			return exitFailure, fmt.Sprintf("control plane error (HTTP %d): %s", e.Status, e.Message)
		}
		return exitFailure, fmt.Sprintf("HTTP %d: %s", e.Status, e.Message)
	}
}

// isConflict reports whether err is a 409, and hands back the typed error so a
// caller can read the fields its route puts in the body.
func isConflict(err error) (*adminclient.APIError, bool) {
	var api *adminclient.APIError
	if errors.As(err, &api) && api.Status == http.StatusConflict {
		return api, true
	}
	return nil, false
}

// indent prefixes every line, for embedding a rendered list inside a message.
func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n")
}
