package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/griffithind/orbit/internal/adminclient"
)

// auditCmd reads the trail.
//
// Every filter the API accepts is offered, and an unparseable bound is refused
// here rather than dropped, for the reason handleListAudit gives for refusing it
// server-side: a filter that is silently ignored returns a full unfiltered page
// as the answer to a narrow question, and "nothing happened in that hour" is the
// wrong thing to conclude during an incident.
func auditCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	var o options
	o.bind(fs)
	var (
		action     = fs.String("action", "", "exact action, e.g. ca.activated")
		targetType = fs.String("target-type", "", "host, role, ca, token, network")
		targetID   = fs.String("target-id", "", "uuid of the target")
		since      = fs.String("since", "", "RFC3339 lower bound, or a duration like 24h")
		until      = fs.String("until", "", "RFC3339 upper bound, or a duration like 1h")
		limit      = fs.Int("limit", 0, "rows to return, up to 1000")
		meta       = fs.Bool("meta", false, "print each entry's metadata")
	)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}
	if err := o.load(); err != nil {
		return err
	}

	f := adminclient.AuditFilter{
		Action:     *action,
		TargetType: *targetType,
		TargetID:   *targetID,
		Limit:      *limit,
	}
	var err error
	if f.Since, err = parseWhen(*since, "-since"); err != nil {
		return err
	}
	if f.Until, err = parseWhen(*until, "-until"); err != nil {
		return err
	}

	res, err := o.client.ListAudit(ctx, f)
	if err != nil {
		return err
	}
	if o.json {
		return emitJSON(res.Raw)
	}

	t := newTable(o.r,
		column{name: "AT"},
		column{name: "ACTOR", elastic: true},
		column{name: "ACTION"},
		column{name: "TARGET"},
		column{name: "SOURCE", optional: true},
	)
	for _, a := range res.Value {
		actor := a.ActorDisplay
		if actor == "" {
			actor = a.ActorType + " " + a.ActorID
		}
		target := a.TargetType
		if a.TargetID != "" {
			target += " " + a.TargetID
		}
		t.add(a.At.Format(time.RFC3339), actor, a.Action, target, a.SourceIP)
	}
	if t.empty() {
		fmt.Fprintln(errOut, "no audit entries match")
		return nil
	}
	t.render(out)

	if *meta {
		fmt.Fprintln(out)
		for _, a := range res.Value {
			if len(a.Meta) == 0 || string(a.Meta) == "{}" {
				continue
			}
			fmt.Fprintf(out, "%s  %s\n%s\n\n",
				a.At.Format(time.RFC3339), a.Action, indent(prettyJSON(a.Meta), "  "))
		}
	}
	return nil
}

// parseWhen accepts an RFC3339 instant or a bare duration meaning "ago".
//
// The duration form is the one an operator actually types — `-since 24h` during
// an incident, not an ISO timestamp they had to compute. The API takes only
// RFC3339, so the conversion happens here; a value that is neither is refused
// rather than dropped, because a dropped bound widens the window silently.
func parseWhen(v, flagName string) (time.Time, error) {
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		if d < 0 {
			d = -d
		}
		return time.Now().Add(-d), nil
	}
	return time.Time{}, usageErrorf(
		"%s %q is neither an RFC3339 timestamp (2026-01-02T15:04:05Z) nor a duration (24h, 30m)",
		flagName, strings.TrimSpace(v))
}
