package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/griffithind/orbit/internal/mesh"
)

// mesh.Config is built from a struct literal in one place and completed in
// another, and every field omitted from either is silently zero.
//
// That is not hypothetical. ListenPort was missing from both for the life of
// v0.1.0 and v0.2.0, so -nebula-port reached every managed host's rendered
// configuration and never reached the control plane's own. A control plane that
// was also a lighthouse therefore rendered am_lighthouse with listen.port 0,
// which nebula refuses — and the refusal was invisible, because the failure
// path deadlocked before main() could print it.
//
// Reading the source is crude. The alternative is booting orbitd against a real
// Postgres and a real network, which is what the deployment did, once, by hand.
func TestEveryMeshConfigFieldIsPopulated(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)

	typ := reflect.TypeOf(mesh.Config{})
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		// Either set in the literal (`mesh.Config{Name: …}`) or assigned onto
		// it before Join (`mc.Name = …`).
		if strings.Contains(text, name+":") || strings.Contains(text, "mc."+name+" =") {
			continue
		}
		t.Errorf("mesh.Config.%s is never set in cmd/orbitd.\n"+
			"It will be the zero value on every network the control plane joins. "+
			"If that is deliberate, assign it explicitly so the choice is visible.", name)
	}
}
