package main

import (
	"bytes"
	"context"
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
