package generation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeNebula writes a shell script standing in for the nebula binary: it exits
// with `code` and prints `output`.
//
// A real executable rather than a stubbed interface, because the thing under
// test is precisely the exec boundary — how an exit status is read, how output
// is carried back, and how "could not run it" is told apart from "it said no".
// A fake ConfigValidator would assert none of that.
func fakeNebula(t *testing.T, code int, output string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script stand-in is not portable to windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "nebula")
	script := "#!/bin/sh\n" +
		"printf '%s' " + shellQuote(output) + " >&2\n" +
		"exit " + itoa(code) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestValidatorAcceptsWhatNebulaAccepts(t *testing.T) {
	v := NebulaBinaryValidator{Binary: fakeNebula(t, 0, "")}
	if err := v.Validate(context.Background(), "/dev/null"); err != nil {
		t.Errorf("a config nebula accepted was reported as bad: %v", err)
	}
}

// TestValidatorCarriesNebulasReason. "nebula rejects the configuration" with no
// detail sends an operator to reproduce by hand what the agent has already been
// told. The reason is the whole value of asking.
func TestValidatorCarriesNebulasReason(t *testing.T) {
	v := NebulaBinaryValidator{Binary: fakeNebula(t, 1, "invalid firewall rule: unknown proto \"tcpp\"")}

	err := v.Validate(context.Background(), "/dev/null")
	if err == nil {
		t.Fatal("a config nebula rejected was accepted")
	}
	if errors.Is(err, ErrValidationUnavailable) {
		t.Fatalf("a rejection was reported as the validator being unavailable: %v", err)
	}
	if !strings.Contains(err.Error(), "unknown proto") {
		t.Errorf("nebula's reason was dropped: %v", err)
	}
}

// TestMissingBinaryIsUnavailableNotRejection is the distinction the whole file
// turns on. If "no nebula installed" arrived as a rejection, a host whose nebula
// lives somewhere unexpected would refuse every generation forever and never
// converge — while reporting a configuration problem that does not exist.
func TestMissingBinaryIsUnavailableNotRejection(t *testing.T) {
	v := NebulaBinaryValidator{Binary: filepath.Join(t.TempDir(), "definitely-not-here")}

	err := v.Validate(context.Background(), "/dev/null")
	if err == nil {
		t.Fatal("a missing validator reported success")
	}
	if !errors.Is(err, ErrValidationUnavailable) {
		t.Errorf("a missing binary was reported as a bad configuration: %v", err)
	}
}

// TestValidationDefaultsOnRatherThanOff. Applier is built from a struct literal
// at every call site, and a field omitted from a literal is silent. If nil
// Validator meant "off", the call site that forgot it would lose the agent's
// strongest guard with nothing to show for it — and every test harness would
// have forgotten it too, so nothing would fail.
func TestValidationDefaultsOnRatherThanOff(t *testing.T) {
	a := &Applier{}
	if a.validator() == nil {
		t.Fatal("an Applier that does not mention validation got none.\n" +
			"That is the state where every host applies unchecked configurations\n" +
			"and no test, log line, or error says so.")
	}
	if _, ok := a.validator().(NebulaBinaryValidator); !ok {
		t.Errorf("the default is %T, not the nebula binary check", a.validator())
	}
}

func TestValidationCanBeDisabledDeliberately(t *testing.T) {
	a := &Applier{DisableValidation: true}
	if a.validator() != nil {
		t.Error("DisableValidation did not disable it")
	}
	if got := a.validatorName(); got != "disabled" {
		t.Errorf("validatorName() = %q, want \"disabled\" so a log line says so", got)
	}
}

func TestAnExplicitValidatorWins(t *testing.T) {
	want := NebulaBinaryValidator{Binary: "/somewhere/else/nebula"}
	a := &Applier{Validator: want, NebulaBinary: "ignored"}
	if got := a.validator(); got != ConfigValidator(want) {
		t.Errorf("validator() = %v, want the one supplied", got)
	}
}

// TestNebulaBinaryFlagReachesTheValidator. NebulaBinary is a flag on a command
// and a field on a struct, joined by one line. That join is exactly the kind
// that gets written on one side only.
func TestNebulaBinaryFlagReachesTheValidator(t *testing.T) {
	a := &Applier{NebulaBinary: "/opt/nebula/bin/nebula"}
	v, ok := a.validator().(NebulaBinaryValidator)
	if !ok {
		t.Fatalf("default validator is %T", a.validator())
	}
	if v.Binary != "/opt/nebula/bin/nebula" {
		t.Errorf("Binary = %q; the configured path never reached the check", v.Binary)
	}
	if !strings.Contains(a.validatorName(), "/opt/nebula/bin/nebula") {
		t.Errorf("validatorName() = %q; a log line would not say which binary answered", a.validatorName())
	}
}
