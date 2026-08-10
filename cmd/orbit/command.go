package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
)

// The command tree.
//
// One declarative table rather than a switch per group. The switch version had
// grown three dialects of "unknown subcommand", nine flag sets still named after
// a command renamed two releases ago, and forty copies of the same six lines of
// scaffolding — and because every FlagSet was ExitOnError, all forty of the
// error checks around parseFlags were unreachable.
//
// What the table buys, beyond the line count: a single place to hang shell
// completion, `orbit help --json` for documentation generation, and the
// Mutating bit, which makes the environment announcement structural instead of
// something each author remembers. Seven mutating commands did not announce —
// including `membership authorize`, which admits a machine to the network,
// while `membership block`, which is reversible, did.

type command struct {
	// Name is the verb as typed. Full path is derived from the parents.
	Name string

	// Short is one line, shown in the parent's listing.
	Short string

	// Args describes the operands, e.g. "<name|uuid>". Empty means none.
	Args string

	// Long is optional extra help, printed under the usage line.
	Long string

	// Aliases are alternative spellings that behave identically.
	Aliases []string

	// MinArgs and MaxArgs bound the operand count. MaxArgs -1 is unbounded.
	MinArgs, MaxArgs int

	// Network makes the runner resolve -network before Run is called.
	Network bool

	// Mutating marks a command that changes the control plane. It implies the
	// environment announcement, so "which control plane am I about to change"
	// is answered by the table rather than by each author remembering.
	Mutating bool

	// Hidden keeps it out of listings without disabling it. For `debug`, whose
	// help says it is not a stable interface.
	Hidden bool

	// Section starts a new heading in the parent's listing. An empty Section
	// continues the previous one, so a run of related commands only names it
	// once and adding a command to a group needs no edit beyond the line.
	Section string

	// Raw passes args to Run untouched, with no flag parsing and no operand
	// check.
	//
	// For groups that still do their own dispatch: parsing here would reject
	// the leaf's flags as undefined before the group ever saw them. It exists
	// to make the migration incremental and should be gone when the last group
	// moves into the table.
	Raw bool

	// Flags registers this command's own flags.
	Flags func(*flag.FlagSet)

	// Run does the work. Exactly one of Run or Subs is set.
	Run func(ctx context.Context, args []string) error

	// Subs are child commands.
	Subs []*command
}

// find resolves a name or alias among the children.
func (c *command) find(name string) *command {
	for _, s := range c.Subs {
		if s.Name == name {
			return s
		}
		for _, a := range s.Aliases {
			if a == name {
				return s
			}
		}
	}
	return nil
}

// dispatch walks the tree and runs the command args names.
//
// path carries the verbs consumed so far, so help and flag-set names read as
// the operator typed them — "orbit membership ls", not "ls". Nine flag sets in
// membership.go were still named "host ls" after the rename, which meant every
// usage error in that file described a command that does not exist.
func (c *command) dispatch(ctx context.Context, path string, args []string) error {
	if path == "" {
		path = c.Name
	}

	if len(c.Subs) > 0 {
		if len(args) == 0 {
			return c.usage(path, nil)
		}
		switch args[0] {
		case "-h", "--help", "help":
			// Help that was ASKED for is a success. Help printed because of a
			// mistake is exit 2. Conflating them means a script cannot tell
			// `orbit --help` from a typo, and `orbit --help` in a Makefile
			// fails the build.
			_ = c.usage(path, nil)
			return &exitError{code: exitOK}
		}
		if strings.HasPrefix(args[0], "-") {
			return usageErrorf("%s takes a subcommand, not a flag; try \"%s --help\"", path, path)
		}
		sub := c.find(args[0])
		if sub == nil {
			_ = c.usage(path, nil)
			what := "subcommand"
			if path == "orbit" {
				what = "command"
			}
			return usageErrorf("unknown %s %q", what, args[0])
		}
		return sub.dispatch(ctx, path+" "+sub.Name, args[1:])
	}

	if c.Raw {
		return c.Run(ctx, args)
	}

	// ContinueOnError, not ExitOnError. Under ExitOnError fs.Parse calls
	// os.Exit(2) before returning, which made every error check around
	// parseFlags unreachable AND sent flag errors to the real stderr rather
	// than through the errOut seam the tests replace.
	fs := flag.NewFlagSet(path, flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() { _ = c.usage(path, fs) }
	if c.Flags != nil {
		c.Flags(fs)
	}
	if err := parseLeaf(fs, args); err != nil {
		if err == flag.ErrHelp {
			return &exitError{code: exitOK}
		}
		return &exitError{code: exitUsage}
	}

	if n := fs.NArg(); n < c.MinArgs || (c.MaxArgs >= 0 && n > c.MaxArgs) {
		_ = c.usage(path, fs)
		return usageErrorf("%s takes %s", path, c.argSpec())
	}
	return c.Run(ctx, fs.Args())
}

func (c *command) argSpec() string {
	switch {
	case c.MaxArgs == 0:
		return "no arguments"
	case c.MinArgs == c.MaxArgs:
		return fmt.Sprintf("exactly %d argument(s): %s", c.MinArgs, c.Args)
	case c.MaxArgs < 0:
		return fmt.Sprintf("at least %d argument(s): %s", c.MinArgs, c.Args)
	}
	return fmt.Sprintf("%d to %d arguments: %s", c.MinArgs, c.MaxArgs, c.Args)
}

// usage prints help to stderr and returns the usage exit class.
//
// Always exitUsage. An explicitly requested --help is intercepted by dispatch,
// which prints the same text and returns exitOK — so the two cases print
// identically and exit differently, which is the distinction clig.dev asks for
// and the old subUsage did not make.
func (c *command) usage(path string, fs *flag.FlagSet) error {
	var b strings.Builder

	line := path
	if !strings.HasPrefix(line, "orbit") {
		line = "orbit " + line
	}
	if len(c.Subs) > 0 {
		line += " <subcommand>"
	}
	if c.Args != "" {
		line += " " + c.Args
	}
	if len(c.Subs) == 0 {
		line += " [flags]"
	}
	fmt.Fprintf(&b, "%s\n", line)

	if c.Long != "" {
		fmt.Fprintf(&b, "\n%s\n", strings.TrimSpace(c.Long))
	}

	if len(c.Subs) > 0 {
		var visible []*command
		width := 0
		for _, s := range c.Subs {
			if s.Hidden {
				continue
			}
			visible = append(visible, s)
			if len(s.Name) > width {
				width = len(s.Name)
			}
		}
		section := ""
		started := false
		for _, s := range visible {
			if s.Section != "" && s.Section != section {
				section = s.Section
				fmt.Fprintf(&b, "\n%s\n", section)
				started = true
			} else if !started {
				fmt.Fprintln(&b)
				started = true
			}
			fmt.Fprintf(&b, "  %-*s  %s\n", width, s.Name, s.Short)
		}
		hint := path
		if !strings.HasPrefix(hint, "orbit") {
			hint = "orbit " + hint
		}
		fmt.Fprintf(&b, "\nRun \"%s <subcommand> --help\" for flags.\n", hint)
	}

	errOut.Write([]byte(b.String()))
	if fs != nil && len(c.Subs) == 0 {
		fmt.Fprintln(errOut, "\nFlags:")
		fs.PrintDefaults()
	}
	return &exitError{code: exitUsage}
}

// parseLeaf parses a leaf command's flags.
//
// Leaves used flag.ContinueOnError, under which fs.Parse calls os.Exit itself. The
// exit codes that produced were right by luck — 2 for a bad flag, 0 for -h,
// which is what this returns — but it wrote to fs.Output() rather than the
// errOut seam the tests replace, and it made all 41 error checks around
// parseFlags unreachable.
//
// ContinueOnError plus this wrapper keeps the codes and routes everything
// through one path.
func parseLeaf(fs *flag.FlagSet, args []string) error {
	fs.SetOutput(errOut)
	if err := parseFlags(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return &exitError{code: exitOK}
		}
		return &exitError{code: exitUsage}
	}
	return nil
}
