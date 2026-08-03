package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
)

// whoamiCmd describes the credential in use.
//
// The most common question a CLI answers, and the one an operator with three
// tokens in three shells asks before every other command.
//
// It renders here rather than fetching ?format=text. The server has that
// renderer for scripts/check-break-glass.sh, which parses it with sed from cron
// on a machine that may lack jq — which makes its exact layout a compatibility
// surface. A second consumer would be the thing that eventually moves a column
// and quietly breaks a recovery check nobody runs until they need it.
func whoamiCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("whoami", flag.ExitOnError)
	var o options
	o.bind(fs)
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := o.load(); err != nil {
		return err
	}

	res, err := o.client.WhoAmI(ctx)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	w := res.Value
	fmt.Fprintf(out, "%-9s %s\n", "url", o.url)
	if o.profileName != "" {
		fmt.Fprintf(out, "%-9s %s\n", "profile", o.profileName)
	}
	fmt.Fprintf(out, "%-9s %s\n", "kind", w.Kind)
	fmt.Fprintf(out, "%-9s %s\n", "id", w.ID)
	if w.Name != "" {
		fmt.Fprintf(out, "%-9s %s\n", "name", w.Name)
	}
	fmt.Fprintf(out, "%-9s %s\n", "scopes", strings.Join(w.Scopes, ", "))

	if w.ExpiresAt == "" {
		fmt.Fprintf(out, "%-9s never\n", "expires")
	} else {
		line := fmt.Sprintf("%-9s %s", "expires", w.ExpiresAt)
		if w.ExpiresInDays != nil {
			line += fmt.Sprintf("  (%d days)", *w.ExpiresInDays)
		}
		fmt.Fprintln(out, line)
	}

	if w.Unscoped {
		// Worth saying every time. A "*" credential passes every scope check,
		// which is correct for break-glass and wrong for the shell somebody left
		// open, and nothing else in this output distinguishes them.
		fmt.Fprintf(errOut,
			"\nThis token holds \"*\" and passes every scope check. If it is not the "+
				"break-glass\ncredential, use a narrower one:\n\n"+
				"  orbit token create -name %s-narrow -scopes hosts:read,networks:read\n",
			orDash(w.Name))
	}
	return nil
}
