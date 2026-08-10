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
