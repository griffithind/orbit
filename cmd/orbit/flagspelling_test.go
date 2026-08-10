package main

import (
	"flag"
	"testing"
)

// TestBothFlagSpellingsParse.
//
// ADR-0005 made --flag canonical and the documentation was rewritten to match,
// but -flag keeps working: stdlib flag treats one dash and two identically, and
// e2e still exercises the single-dash form deliberately.
//
// Pinned rather than assumed, because the alternative was adopting a framework.
// pflag — and therefore cobra — reads -json as the shorthand cluster -j -s -o -n
// and fails, which is what ADR-0004 turns on. If this test ever fails, the flag
// parser has been replaced with one that does not honour the older spelling, and
// every script anyone wrote against it breaks silently.
func TestBothFlagSpellingsParse(t *testing.T) {
	for _, spelling := range []string{"-json", "--json"} {
		t.Run(spelling, func(t *testing.T) {
			fs := flag.NewFlagSet("probe", flag.ContinueOnError)
			fs.SetOutput(errOut)
			got := fs.Bool("json", false, "")

			if err := parseFlags(fs, []string{spelling}); err != nil {
				t.Fatalf("%s did not parse: %v", spelling, err)
			}
			if !*got {
				t.Errorf("%s parsed but did not set the flag", spelling)
			}
		})
	}
}

// TestFlagsAfterOperandsStillParse is the bug parseFlags exists to fix, and the
// one that disqualified peterbourgon/ff: `membership show web-01 --json`
// returned json=false with a nil error there.
func TestFlagsAfterOperandsStillParse(t *testing.T) {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(errOut)
	asJSON := fs.Bool("json", false, "")
	network := fs.String("network", "", "")

	// The hard case: a flag with a value, then an operand, then a bool flag.
	// Deciding that "prod" is a value and "web-01" is an operand needs the
	// FlagSet, which is why parseFlags walks it instead of pattern-matching.
	if err := parseFlags(fs, []string{"--network", "prod", "web-01", "--json"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !*asJSON {
		t.Error("--json after an operand was silently dropped")
	}
	if *network != "prod" {
		t.Errorf("network = %q, want prod", *network)
	}
	if got := fs.Args(); len(got) != 1 || got[0] != "web-01" {
		t.Errorf("operands = %v, want [web-01]", got)
	}
}
