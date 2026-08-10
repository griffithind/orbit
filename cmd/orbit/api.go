package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// `orbit api` — an authenticated request against the admin API.
//
// The CLI stops being a ceiling. Every route this binary has not wrapped is
// still reachable, with the profile, URL and token already resolved — which is
// the whole difference from curl, where each of those has to be restated and
// the token ends up in shell history or in ps.
//
// ZeroTier arrived at the same idea from the other end: any argument beginning
// with "/" is passed through to its local API. `gh api` is the same shape,
// reached much later. It is the one thing worth taking from zerotier-cli
// outright.
//
// The body is emitted verbatim, like every other -json path here, so
// `orbit api /v1/networks | jq` and `curl … | jq` are interchangeable.

func apiCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("api", flag.ContinueOnError)
	var o options
	o.bind(fs)
	var (
		method = fs.String("method", "", "HTTP method; GET unless a body is supplied, then POST")
		data   = fs.String("data", "", "request body, or @file to read one, or @- for stdin")
	)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usageErrorf("usage: orbit api [--method M] [--data BODY] <path>\n\n" +
			"  orbit api /v1/networks\n" +
			"  orbit api --method POST --data @role.json /v1/networks/prod/roles\n\n" +
			"The path starts with / and is everything after the base URL.")
	}
	if err := o.load(); err != nil {
		return err
	}

	path := fs.Arg(0)
	if !strings.HasPrefix(path, "/") {
		return usageErrorf("the path must start with /, got %q\n\n"+
			"It is the part after the base URL: /v1/networks, not %s/v1/networks",
			path, o.url)
	}

	body, err := readBody(*data)
	if err != nil {
		return err
	}

	// Default GET, and POST only when a body was given. Anything destructive
	// has to be named: a typo that turns a listing into a DELETE is exactly the
	// failure this command's convenience would otherwise introduce.
	m := strings.ToUpper(*method)
	if m == "" {
		m = http.MethodGet
		if len(body) > 0 {
			m = http.MethodPost
		}
	}
	if m != http.MethodGet && m != http.MethodHead {
		o.announce(fmt.Sprintf("About to send %s %s", m, path))
	}

	raw, status, err := o.client.Raw(ctx, m, path, body)
	if err != nil {
		return err
	}

	if len(raw) > 0 {
		if err := emitJSON(raw); err != nil {
			return err
		}
	}

	// The status on stderr, so it never contaminates a piped body, and only
	// when it is not the ordinary success — a 200 said out loud on every call
	// is noise that trains people to stop reading it.
	if status < 200 || status >= 300 {
		fmt.Fprintf(errOut, "\nHTTP %d\n", status)
		return &exitError{code: exitFailure}
	}
	if status != http.StatusOK {
		fmt.Fprintf(errOut, "HTTP %d\n", status)
	}
	return nil
}

// readBody resolves --data: a literal, @file, or @- for stdin.
func readBody(spec string) ([]byte, error) {
	switch {
	case spec == "":
		return nil, nil
	case spec == "@-":
		return io.ReadAll(os.Stdin)
	case strings.HasPrefix(spec, "@"):
		b, err := os.ReadFile(spec[1:])
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", spec[1:], err)
		}
		return b, nil
	}
	return []byte(spec), nil
}
