package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// The environment announcement, enforced.
//
// config.go states the failure it guards: "blocking a prod host while believing
// you are in staging". announce() prints the url, profile and network before the
// change, and it is the only thing between an operator with two shells and an
// outage.
//
// It was a habit, and habits are unevenly kept. Seven mutating commands said
// nothing — including `membership authorize`, which admits a machine and
// allocates its address, and `ca create`, whose claim cannot be widened
// afterwards — while `membership block`, which is reversible, announced.
//
// Both directions are checked. A command that mutates without announcing is the
// bug; a command that announces without being marked would satisfy the first
// test for the wrong reason and leave the table lying to the next reader.
//
// The check is static because leaves still parse their own flags: there is no
// seam to run them through without a control plane. When they move into the
// table the announcement moves with them and both tests can go.

func TestEveryMutatingCommandAnnounces(t *testing.T) {
	announcers := functionsCalling(t, "announce")

	var missing []string
	for fn := range mutatingTargets(t) {
		if !announcers[fn] {
			missing = append(missing, fn)
		}
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		t.Errorf("marked Mutating in tree.go but never calls o.announce:\n  %s\n\n"+
			"Each changes the control plane without saying WHICH control plane.\n"+
			"Add o.announce(...) after o.load() and before the mutation.",
			strings.Join(missing, "\n  "))
	}
}

func TestMutatingMarkingIsComplete(t *testing.T) {
	marked := mutatingTargets(t)

	var unmarked []string
	for fn := range functionsCalling(t, "announce") {
		if !marked[fn] {
			unmarked = append(unmarked, fn)
		}
	}
	sort.Strings(unmarked)

	if len(unmarked) > 0 {
		t.Errorf("calls o.announce but tree.go does not mark it mutating:\n  %s\n\n"+
			"Use mutating() rather than leaf() in the table, or drop the announcement.",
			strings.Join(unmarked, "\n  "))
	}
}

// mutatingTargets is the set of leaf functions reached from a mutating() entry.
//
// Keyed by the function rather than by the verb, because verbs collide: rm,
// create, revoke and use each appear under several nouns, and a verb-keyed map
// silently kept only the last one. That version of this test reported six false
// failures, which is the good outcome — the first version matched strings,
// matched nothing, and PASSED.
func mutatingTargets(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "tree.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		id, ok := call.Fun.(*ast.Ident)
		if !ok || id.Name != "mutating" || len(call.Args) < 3 {
			return true
		}
		// The last argument is the closure; the single call inside it is the
		// leaf function.
		ast.Inspect(call.Args[len(call.Args)-1], func(n ast.Node) bool {
			inner, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if fn, ok := inner.Fun.(*ast.Ident); ok {
				out[fn.Name] = true
				return false
			}
			return true
		})
		return true
	})

	if len(out) == 0 {
		t.Fatal("tree.go declares no mutating() commands; this test would pass vacuously")
	}
	return out
}

// functionsCalling returns the top-level functions in this package whose body
// contains a call to the named method.
func functionsCalling(t *testing.T, method string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == method {
					out[fn.Name.Name] = true
					return false
				}
				return true
			})
		}
	}

	if len(out) == 0 {
		t.Fatalf("nothing calls %q; the parser found nothing, so this test would "+
			"pass vacuously", method)
	}
	return out
}
