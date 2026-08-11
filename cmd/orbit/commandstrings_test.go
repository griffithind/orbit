package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Every command this program tells somebody to run must exist.
//
// The bug this pins cost three e2e tests and fourteen strings. `join` was
// promoted from `orbit agent join` to `orbit join` — the tree changed, the
// tests that named the new spelling were written, and nothing updated the
// strings that hand the old one to an operator: the error from `agent run` with
// no networks, the install hint, the reserve handout in both the CLI and the
// web UI, and orbitd's bootstrap output. All of them named a subcommand that
// had stopped existing, and the tree could not tell because a string is not a
// call.
//
// e2e caught three of the fourteen, eventually. This catches all of them in
// milliseconds, on the commit that breaks them, which is the difference between
// a rename that is finished and one that is merely started.
func TestEveryCommandWeTellPeopleToRunExists(t *testing.T) {
	root := rootCommand()

	// Only invocations, not every sentence containing the word "orbit".
	//
	// The codebase has one convention for a command it wants somebody to run:
	// it is in backticks, indented on its own line, or prefixed with sudo. That
	// is what separates "run `orbit status`" from "the orbit agent is not
	// running", where "agent" is a noun and "is" is a verb.
	invocation := regexp.MustCompile("(?:`|^|\\n)\\s*(?:sudo )?orbit((?: [a-z][a-z0-9-]*)+)")

	checked := 0
	for _, path := range goFilesUnder(t, "..", "../../internal") {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			continue // not our problem here; the build catches it
		}

		report := func(pos token.Pos, text string) {
			for _, m := range invocation.FindAllStringSubmatch(text, -1) {
				words := strings.Fields(m[1])
				node, walked := root, []string{}
				for _, w := range words {
					next := node.find(w)
					if next == nil {
						// A leaf's remaining words are its arguments, and prose
						// that merely begins with "orbit" is not an invocation
						// at all — only an unresolved word under a GROUP is a
						// command that does not exist.
						if len(node.Subs) > 0 && len(walked) > 0 {
							t.Errorf("%s: %q names `orbit %s %s`, but %q has no subcommand %q",
								fset.Position(pos), strings.TrimSpace(m[0]),
								strings.Join(walked, " "), w, strings.Join(walked, " "), w)
						}
						break
					}
					node, walked = next, append(walked, w)
				}
				if len(walked) > 0 {
					checked++
				}
			}
		}

		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					report(lit.Pos(), s)
				}
			}
			return true
		})
		// Literals only. A doc comment saying "this replaced `orbit membership
		// create`" is accurate history about a command that is gone on purpose;
		// a string handed to an operator naming the same thing is a broken
		// instruction. Only the second is a defect.
	}

	// This test is only as good as what it finds to look at. A refactor that
	// moves these strings somewhere the walk does not reach would leave it
	// passing while checking nothing.
	if checked < 50 {
		t.Fatalf("only %d invocations found; this test has stopped seeing most of them", checked)
	}
	t.Logf("checked %d invocations", checked)
}

func goFilesUnder(t *testing.T, roots ...string) []string {
	t.Helper()
	var out []string
	for _, r := range roots {
		err := filepath.Walk(r, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() && (info.Name() == "third_party" || info.Name() == "node_modules") {
				return filepath.SkipDir
			}
			if strings.HasSuffix(p, ".go") {
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(out) == 0 {
		t.Fatal("found no Go files to scan")
	}
	return out
}
