package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Rendering happens here, on the client, and never by asking the server for
// text.
//
// The server does have ?format=text, on exactly two routes, and internal/api/
// convergence.go says why: scripts/check-break-glass.sh parses renderWhoAmI with
// sed, from cron, on a machine that may have neither jq nor a working overlay.
// That makes those two renderers a compatibility surface. A CLI that consumed
// them would become a second constituency with its own layout opinions, and the
// first time one of them wanted a column moved, a recovery check would silently
// stop matching. So the CLI fetches JSON and lays it out itself.

// defaultWidth is what a terminal is assumed to be when it will not say.
//
// 80 rather than something wider: too narrow only drops optional columns, while
// too wide wraps every row and destroys the table entirely.
const defaultWidth = 80

// narrowWidth is where the lower-priority columns go. Below roughly a hundred
// columns there is not room for both the identifying fields and the diagnostic
// ones, and the identifying fields are the ones the next command needs.
const narrowWidth = 100

// out is where results go, and errOut where prose does. Variables rather than
// os.Stdout directly so tests can capture them.
var (
	out    io.Writer = os.Stdout
	errOut io.Writer = os.Stderr
)

// stdoutIsTTY reports whether stdout is a terminal.
//
// os.Stdout.Stat and os.ModeCharDevice, from the standard library, rather than
// golang.org/x/term. The CLI must stay installable without dragging in anything
// the control plane does not already need, and this is the whole of what it uses
// a terminal library for.
func stdoutIsTTY() bool { return isTTY(os.Stdout) }

// stderrIsTTY gates progress reporting, which is written to stderr and rewrites
// its own line with a carriage return. Into a log file that produces one very
// long line of superimposed updates, so off a terminal the same information is
// printed one line per poll instead.
func stderrIsTTY() bool { return isTTY(os.Stderr) }

func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// termWidth is the usable width.
//
// $COLUMNS first: it is what a shell exports, it is what a user can override,
// and it needs no ioctl. Anything unparseable or absurd falls back rather than
// producing a table one column wide.
func termWidth() int {
	if v := os.Getenv("COLUMNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 40 && n <= 1000 {
			return n
		}
	}
	return defaultWidth
}

// piped output is deliberately plain: no truncation, no colour, no footer.
//
// The point is that `orbit host ls | awk '{print $1}'` keeps working. An
// ellipsis in a hostname is a value the next command cannot use, an ANSI escape
// is a byte awk will happily include in a field, and a summary line is a row
// that is not a row.
type renderer struct {
	tty   bool
	width int
}

func newRenderer() renderer {
	tty := stdoutIsTTY()
	w := termWidth()
	if !tty {
		// Effectively unbounded, so nothing is truncated or dropped.
		w = 1 << 20
	}
	return renderer{tty: tty, width: w}
}

// column describes one table column.
type column struct {
	name string

	// elastic marks the column that absorbs whatever width is left, and is
	// truncated with an ellipsis when there is not enough. Exactly one column is
	// elastic — NAME, because it is the only field whose length is unbounded and
	// the only one an operator can still recognise from a prefix.
	elastic bool

	// optional columns are dropped on a narrow terminal, lowest priority first.
	optional bool

	// right aligns numbers.
	right bool
}

type table struct {
	cols []column
	rows [][]string
	r    renderer
}

func newTable(r renderer, cols ...column) *table {
	return &table{cols: cols, r: r}
}

func (t *table) add(cells ...string) {
	t.rows = append(t.rows, cells)
}

func (t *table) empty() bool { return len(t.rows) == 0 }

// render lays the table out and writes it.
func (t *table) render(w io.Writer) {
	keep := make([]int, 0, len(t.cols))
	for i := range t.cols {
		keep = append(keep, i)
	}

	// Natural width of every column, header included.
	natural := make([]int, len(t.cols))
	for i, c := range t.cols {
		natural[i] = width(c.name)
	}
	for _, row := range t.rows {
		for i := range t.cols {
			if i < len(row) && width(row[i]) > natural[i] {
				natural[i] = width(row[i])
			}
		}
	}

	const gap = 2
	total := func(idx []int) int {
		n := 0
		for _, i := range idx {
			n += natural[i] + gap
		}
		return n - gap
	}

	// Drop optional columns from the right while the table does not fit, and
	// only on a narrow terminal. Dropping in the other order would take away the
	// name before the version.
	if t.r.width < narrowWidth {
		for total(keep) > t.r.width {
			dropped := false
			for i := len(keep) - 1; i >= 0; i-- {
				if t.cols[keep[i]].optional {
					keep = append(keep[:i], keep[i+1:]...)
					dropped = true
					break
				}
			}
			if !dropped {
				break
			}
		}
	}

	// Give the elastic column whatever is left over, and never less than a
	// handful of characters — a name cut to two letters identifies nothing.
	if over := total(keep) - t.r.width; over > 0 {
		for _, i := range keep {
			if t.cols[i].elastic {
				natural[i] = max(natural[i]-over, 8)
				break
			}
		}
	}

	line := func(cells func(i int) string) {
		var b strings.Builder
		for n, i := range keep {
			s := cells(i)
			if width(s) > natural[i] {
				s = truncate(s, natural[i])
			}
			last := n == len(keep)-1
			switch {
			case t.cols[i].right:
				b.WriteString(pad(s, natural[i], true))
			case last:
				// No trailing padding on the final column: it is invisible on a
				// terminal and it is whitespace a pipeline has to strip.
				b.WriteString(s)
			default:
				b.WriteString(pad(s, natural[i], false))
			}
			if !last {
				b.WriteString(strings.Repeat(" ", gap))
			}
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}

	line(func(i int) string { return t.cols[i].name })
	for _, row := range t.rows {
		line(func(i int) string {
			if i < len(row) {
				return row[i]
			}
			return ""
		})
	}
}

// footer is a summary line, suppressed when stdout is not a terminal: a
// pipeline reads it as one more row of data.
func (t *table) footer(w io.Writer, format string, args ...any) {
	if !t.r.tty {
		return
	}
	fmt.Fprintf(w, format+"\n", args...)
}

func width(s string) int { return utf8.RuneCountInString(s) }

func pad(s string, n int, right bool) string {
	d := n - width(s)
	if d <= 0 {
		return s
	}
	if right {
		return strings.Repeat(" ", d) + s
	}
	return s + strings.Repeat(" ", d)
}

// truncate cuts to n runes with an ellipsis. Rune-aware, because a hostname may
// legitimately be non-ASCII and cutting mid-sequence produces a replacement
// character the terminal renders as garbage.
func truncate(s string, n int) string {
	if width(s) <= n || n <= 0 {
		return s
	}
	if n == 1 {
		return "…"
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// ansi wraps s in an escape sequence, or returns it unchanged when stdout is not
// a terminal.
func (r renderer) ansi(code, s string) string {
	if !r.tty {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (r renderer) bold(s string) string { return r.ansi("1", s) }

//------------------------------------------------------------------------------
// Times
//------------------------------------------------------------------------------

// ago renders a timestamp the way an operator reads one.
//
// "never" for a host that has not reported, copied from renderConvergence and
// for the reason it states: printing 0001-01-01 makes "has never checked in"
// and "checked in an hour ago" look like the same kind of fact, and they are
// opposite diagnoses.
//
// Relative only in human output. -json emits the API response verbatim, so the
// machine-readable form is always RFC3339 and this never touches it.
func ago(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	d := time.Since(*t)
	if d < 0 {
		// A clock disagreement, and worth showing as one rather than as a
		// negative duration nobody can act on.
		return "in " + shortDuration(-d)
	}
	return shortDuration(d) + " ago"
}

// until renders a deadline: how long is left, or how long ago it passed.
func until(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Until(t)
	if d < 0 {
		return shortDuration(-d) + " ago"
	}
	return "in " + shortDuration(d)
}

// shortDuration is time.Duration.String, rounded to something readable and
// stopping at days. A certificate lifetime in hours is fine; 1176h0m0s is not.
func shortDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < time.Hour:
		return d.Round(time.Second).String()
	case d < 48*time.Hour:
		return d.Round(time.Minute).String()
	default:
		days := int(d.Hours() / 24)
		hours := int(d.Hours()) % 24
		if hours == 0 {
			return fmt.Sprintf("%dd", days)
		}
		return fmt.Sprintf("%dd%dh", days, hours)
	}
}

//------------------------------------------------------------------------------
// JSON
//------------------------------------------------------------------------------

// emitJSON writes the API response exactly as it arrived.
//
// Verbatim, not re-encoded. The docs are still full of curl, so `orbit host ls
// -json | jq` and `curl … | jq` have to be interchangeable — and a re-encode
// would change field order, change how the same numbers are spelled, and drop
// every field this build does not know about. The one thing worth normalising is
// the trailing newline, which the server's json.Encoder already writes.
func emitJSON(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	if _, err := out.Write(raw); err != nil {
		return err
	}
	if raw[len(raw)-1] != '\n' {
		_, err := io.WriteString(out, "\n")
		return err
	}
	return nil
}

// prettyJSON indents a JSON fragment for human display. Used only for values
// that are opaque to the CLI — a role's firewall rules, an audit entry's meta —
// where there is nothing to lay out but the JSON itself.
//
// It indents from column zero; callers that want it inset wrap the result in
// indent(). Doing both here would apply the prefix twice to every line but the
// first, which is how JSON ends up looking like a staircase.
func prettyJSON(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return string(raw)
	}
	return strings.TrimRight(buf.String(), "\n")
}
