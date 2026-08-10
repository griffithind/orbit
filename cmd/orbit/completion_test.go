package main

import (
	"bytes"
	"context"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// completeTo runs __complete and returns the candidates.
func completeTo(t *testing.T, words ...string) []string {
	t.Helper()
	var buf bytes.Buffer
	saved := out
	out = &buf
	defer func() { out = saved }()

	if err := completeCmd(context.Background(), words); err != nil {
		t.Fatalf("__complete %v: %v", words, err)
	}
	s := strings.TrimSpace(buf.String())
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func TestCompleteOffersTopLevelCommands(t *testing.T) {
	got := completeTo(t, "")
	for _, want := range []string{"status", "netcheck", "membership", "join", "api"} {
		if !slices.Contains(got, want) {
			t.Errorf("%q missing from top-level completion: %v", want, got)
		}
	}
}

func TestCompleteFiltersOnThePartialWord(t *testing.T) {
	got := completeTo(t, "net")
	if !slices.Contains(got, "netcheck") || !slices.Contains(got, "network") {
		t.Errorf(`"net" should offer both netcheck and network, got %v`, got)
	}
	if slices.Contains(got, "status") {
		t.Errorf(`"net" offered an unrelated command: %v`, got)
	}
}

// TestCompleteDescendsThroughAliases. `orbit member ls` is a documented
// spelling, so completing it has to work — a completion that only knows the
// canonical name teaches people the alias is wrong.
func TestCompleteDescendsThroughAliases(t *testing.T) {
	canonical := completeTo(t, "membership", "")
	alias := completeTo(t, "member", "")

	if len(alias) == 0 {
		t.Fatal("the member alias completed to nothing")
	}
	if !slices.Equal(canonical, alias) {
		t.Errorf("alias and canonical disagree:\n  membership %v\n  member     %v", canonical, alias)
	}
}

// TestCompleteHidesHiddenCommands. __complete must not offer itself, and
// `debug` — when it exists — is hidden for the same reason: an interface
// documented as unstable should not be advertised by tab.
func TestCompleteHidesHiddenCommands(t *testing.T) {
	if got := completeTo(t, ""); slices.Contains(got, "__complete") {
		t.Errorf("__complete offered itself: %v", got)
	}
}

// TestCompleteRefusesToGuessAfterAnUnknownWord.
//
// Offering the root's verbs here would be worse than offering nothing: the line
// is already not a valid command, and completing it as though it were sends
// somebody further down a path that cannot work.
func TestCompleteRefusesToGuessAfterAnUnknownWord(t *testing.T) {
	if got := completeTo(t, "nosuch", ""); len(got) != 0 {
		t.Errorf("completed after an unknown command: %v", got)
	}
}

func TestCompleteOffersFlags(t *testing.T) {
	got := completeTo(t, "membership", "ls", "--n")
	if !slices.Contains(got, "--network") {
		t.Errorf(`"--n" should offer --network, got %v`, got)
	}
	for _, c := range got {
		if !strings.HasPrefix(c, "--n") {
			t.Errorf("flag completion returned a non-matching candidate %q", c)
		}
	}
}

// TestCompletionScriptsAreEmitted checks the shells are all wired, and that each
// script actually calls __complete — a script that emits nothing would look
// installed and complete nothing.
func TestCompletionScriptsAreEmitted(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			var buf bytes.Buffer
			saved := out
			out = &buf
			defer func() { out = saved }()

			if err := completionCmd(context.Background(), []string{shell}); err != nil {
				t.Fatalf("completion %s: %v", shell, err)
			}
			script := buf.String()
			if !strings.Contains(script, "__complete") {
				t.Errorf("the %s script never calls __complete", shell)
			}
			if !strings.Contains(script, "orbit") {
				t.Errorf("the %s script never names the binary", shell)
			}
		})
	}
}

func TestCompletionRejectsAnUnknownShell(t *testing.T) {
	if err := completionCmd(context.Background(), []string{"nope"}); err == nil {
		t.Fatal("an unknown shell was accepted")
	}
}

// TestCompletedFlagsAreAccepted.
//
// The bug this pins: completion listed the common flags in a literal of its
// own rather than asking the code that registers them. options.bind registers
// "y"; the literal said "--yes". So the shell offered a flag, the user pressed
// tab, and the command answered "flag provided but not defined: -yes".
//
// The assertion is the property, not the spelling: every candidate completion
// offers must be one the command will actually accept. A flag rejected here has
// either been renamed without updating what advertises it, or advertised
// without existing at all — and both look identical to whoever typed it.
func TestCompletedFlagsAreAccepted(t *testing.T) {
	for _, cmd := range [][]string{
		{"membership", "ls"},
		{"policy", "check"},
		{"network", "ls"},
		{"token", "create"},
	} {
		candidates := completeTo(t, append(slices.Clone(cmd), "--")...)
		if len(candidates) == 0 {
			t.Fatalf("%v offered no flags at all", cmd)
		}
		for _, c := range candidates {
			name := strings.TrimPrefix(c, "--")
			var stderr bytes.Buffer
			savedErr := errOut
			errOut = &stderr
			// Parsing happens before anything is dialled, so an unknown flag
			// reports itself without the command needing a control plane.
			_ = rootCommand().dispatch(context.Background(), "",
				append(slices.Clone(cmd), "-"+name))
			errOut = savedErr

			if strings.Contains(stderr.String(), "not defined") {
				t.Errorf("completion offers %q for %v, but the command rejects it:\n%s",
					c, cmd, strings.TrimSpace(stderr.String()))
			}
		}
	}
}

// TestCompletionOffersExactlyWhatEachCommandParses.
//
// The strong form of TestCompletedFlagsAreAccepted, and it checks both
// directions: every flag a command accepts must be offered, and every flag
// offered must be accepted. Either gap is a lie told by the shell.
//
// The command's own -h output is the reference, because that is generated from
// the FlagSet the command actually parses with. Completion builds its set from
// the tree instead, and the point of this test is that those two constructions
// have to agree — the tree is a second description of the same thing, and a
// second description is exactly what goes stale.
//
// Leaves that take no flags at all are skipped rather than required to declare
// an empty set: there is nothing to get wrong.
func TestCompletionOffersExactlyWhatEachCommandParses(t *testing.T) {
	checked := 0
	var walk func(c *command, path []string)
	walk = func(c *command, path []string) {
		if len(c.Subs) > 0 {
			for _, s := range c.Subs {
				walk(s, append(append([]string{}, path...), s.Name))
			}
			return
		}
		if c.Hidden || len(path) == 0 {
			return
		}

		// -h renders the flags from the FlagSet the command parses with.
		var help bytes.Buffer
		savedErr, savedOut := errOut, out
		errOut, out = &help, &help
		_ = rootCommand().dispatch(context.Background(), "", append(append([]string{}, path...), "-h"))
		errOut, out = savedErr, savedOut

		parsed := map[string]bool{}
		for _, line := range strings.Split(help.String(), "\n") {
			if m := regexp.MustCompile(`^\s+-([a-zA-Z][\w-]*)`).FindStringSubmatch(line); m != nil {
				parsed[m[1]] = true
			}
		}
		if len(parsed) == 0 {
			return
		}
		checked++

		offered := map[string]bool{}
		for _, c := range completeTo(t, append(append([]string{}, path...), "--")...) {
			offered[strings.TrimPrefix(c, "--")] = true
		}

		for f := range parsed {
			if !offered[f] {
				t.Errorf("orbit %s accepts -%s but completion never offers it",
					strings.Join(path, " "), f)
			}
		}
		for f := range offered {
			if !parsed[f] {
				t.Errorf("orbit %s completes --%s but does not accept it",
					strings.Join(path, " "), f)
			}
		}
	}
	walk(rootCommand(), nil)

	// The skip for flagless leaves is load-bearing, so it must not quietly grow
	// to cover everything. An earlier run of this test checked far fewer
	// commands than it appeared to: status and peers parsed with fs.Parse
	// rather than parseLeaf, so their usage went to the real stderr instead of
	// the buffer, "parsed" came back empty, and both were skipped in silence.
	if checked < 30 {
		t.Fatalf("only %d commands had flags to check; this test has stopped looking at most of the tree", checked)
	}
}
