package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The two properties of this package that an audit can only establish by
// enumerating, and that nothing therefore keeps true.
//
// Everything else the browser surface rests on already has a test: the cookie's
// __Host- attributes, the form token being per-session, bearer tokens being
// refused, safeNext, the scope rule matching the API's, stored values being
// escaped, no inline script or style. What was left were the two facts that hold
// only because every current call site happens to be written correctly.

// TestEveryMutatingRouteGoesThroughAuthed.
//
// The CSRF check lives inside authed (middleware.go), not in the handlers. That
// is the right place — a check each handler has to remember is one a handler
// will eventually forget — but it means the property "every state-changing route
// is CSRF-protected" is really "every POST is registered through authed", and
// nothing enforced that.
//
// Registering one with s.page(h) instead of s.page(s.authed(scope, h)) compiles,
// serves, and looks like the lines around it. The route would accept a
// cross-site POST, which for this package means a form on someone else's site
// blocking a host or minting an enrollment code in an operator's session.
//
// POST /ui/login is the one exception and is checked separately below.
func TestEveryMutatingRouteGoesThroughAuthed(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "web.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	// The two helpers Routes defines are wrappers; both must themselves wrap
	// authed, or every route registered through them is unprotected at once.
	for _, helper := range []string{"get", "post"} {
		if !helperWrapsAuthed(t, f, helper) {
			t.Fatalf("the %q helper in Routes does not wrap s.authed; "+
				"every route registered through it is unauthenticated", helper)
		}
	}

	// And every route registered directly, bypassing those helpers.
	checked := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Handle" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil || !strings.HasPrefix(pattern, "POST ") {
			return true
		}
		checked++

		if pattern == "POST /ui/login" {
			return true // no session to authenticate against yet; see below
		}
		if !mentions(call.Args[1], "authed") {
			t.Errorf("%s is registered without s.authed, so the CSRF check never runs for it",
				pattern)
		}
		return true
	})

	if checked < 2 {
		t.Fatalf("found %d directly-registered POST routes; this test is not reading Routes", checked)
	}
}

// TestTheLoginPostIsTheOnlyUnauthedPost.
//
// It is exempt for a structural reason — there is no session to derive a form
// token from before signing in — and that exemption must stay exactly one route
// wide. Recorded as a test rather than a comment because the exemption above is
// written as a string comparison, and a second route added beside it would
// inherit the reasoning without inheriting the argument.
func TestTheLoginPostIsTheOnlyUnauthedPost(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "web.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	var unauthed []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Handle" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil || !strings.HasPrefix(pattern, "POST ") {
			return true
		}
		if !mentions(call.Args[1], "authed") {
			unauthed = append(unauthed, pattern)
		}
		return true
	})

	if len(unauthed) != 1 || unauthed[0] != "POST /ui/login" {
		t.Errorf("POST routes outside authed = %v, want exactly [POST /ui/login]. "+
			"A new one needs its own argument for why a cross-site form cannot drive it.", unauthed)
	}
}

// TestNothingBypassesContextualEscaping.
//
// html/template escapes according to where a value lands — text node, attribute,
// URL, script. The named string types are how a caller says "I have already
// made this safe", and text/template is the same waiver by another route: it
// escapes nothing at all.
//
// This package renders operator-supplied names, user agents, audit metadata and
// certificate PEM. There is no such conversion today and no reason for one; a
// test is cheaper than noticing later that a single template.HTML undid the
// whole defence.
func TestNothingBypassesContextualEscaping(t *testing.T) {
	banned := []string{
		"template.HTML(", "template.JS(", "template.URL(",
		"template.HTMLAttr(", "template.JSStr(", "template.CSS(",
		`"text/template"`,
	}

	files := 0
	err := filepath.Walk(".", func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		// This file names them all in order to forbid them.
		if strings.HasSuffix(path, "surface_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		files++
		for _, b := range banned {
			if strings.Contains(string(src), b) {
				t.Errorf("%s uses %s, which turns off contextual escaping for a value "+
					"this package renders from the database", path, strings.TrimSuffix(b, "("))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 10 {
		t.Fatalf("walked only %d Go files; this test is not seeing the package", files)
	}
}

func helperWrapsAuthed(t *testing.T, f *ast.File, name string) bool {
	t.Helper()
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		id, ok := as.Lhs[0].(*ast.Ident)
		if !ok || id.Name != name {
			return true
		}
		if _, ok := as.Rhs[0].(*ast.FuncLit); ok && mentions(as.Rhs[0], "authed") {
			found = true
		}
		return true
	})
	return found
}

// mentions reports whether an expression names a selector anywhere inside it.
func mentions(e ast.Expr, sel string) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if s, ok := n.(*ast.SelectorExpr); ok && s.Sel.Name == sel {
			found = true
		}
		return true
	})
	return found
}
