package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Which decoder each surface uses is a property nothing else keeps true.
//
// Both helpers compile everywhere and neither is wrong on its face, so a handler
// added to the agent surface with the strict one looks exactly like the lines
// around it — and the consequence does not show up until a fleet upgrade, on the
// replica that was upgraded last. See
// docs/adr/0026-a-process-that-disagrees-with-the-schema-refuses-to-serve.md.
//
// The mapping is by FILE rather than by route, because that is how this package
// is laid out: server.go and join.go hold what an agent talks to, admin.go and
// resources.go hold what an operator talks to.
func TestEachSurfaceUsesItsOwnDecoder(t *testing.T) {
	want := map[string]string{
		// Agents and enrolling machines. Tolerant, so a newer agent talking to
		// an older replica degrades instead of taking a permanent 400.
		"server.go": "decodeAgent",
		"join.go":   "decodeAgent",

		// Operators and scripts. Strict, so a misspelled field is an error
		// rather than a change that silently did nothing.
		"admin.go":     "decode",
		"resources.go": "decode",
		"route.go":     "decode",
		"device.go":    "decode",
	}

	checked := 0
	for file, decoder := range want {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || (id.Name != "decode" && id.Name != "decodeAgent") {
				return true
			}
			checked++
			if id.Name != decoder {
				t.Errorf("%s:%d calls %s, want %s for this surface",
					file, fset.Position(call.Pos()).Line, id.Name, decoder)
			}
			return true
		})
	}

	if checked < 15 {
		t.Fatalf("found only %d decode call sites; this test is not reading the package", checked)
	}
}

// TestNoHandlerDecodesDirectly. Both helpers exist so that the strict/tolerant
// choice is made in one place per surface; a handler reaching for
// json.NewDecoder itself opts out of that choice without saying so.
func TestNoHandlerDecodesDirectly(t *testing.T) {
	files := 0
	err := filepath.Walk(".", func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		files++
		// server.go defines decodeBody, which is the one legitimate caller.
		if path == "server.go" {
			return nil
		}
		if strings.Contains(string(src), "json.NewDecoder") {
			t.Errorf("%s calls json.NewDecoder directly; use decode or decodeAgent "+
				"so the strict/tolerant choice stays a per-surface decision", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 5 {
		t.Fatalf("walked only %d Go files; this test is not seeing the package", files)
	}
}
