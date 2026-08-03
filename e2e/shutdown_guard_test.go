package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A wait on nebula's shutdown must always be bounded.
//
// service.Wait blocks until every nebula reader goroutine has exited and the
// interface has released its construction token. A shutdown race that leaves
// one of them parked makes it block forever, and the two places that call it
// are the two places where that is most expensive:
//
//   - in a t.Cleanup it does not fail one test. It hangs the whole package
//     until the go test timeout and every other result is lost with it.
//   - in mesh.Node.Close it makes a control plane that cannot finish shutting
//     down, turning a restart into a SIGKILL.
//
// Both are now bounded. This exists because the bound is invisible at the call
// site a third caller would copy — `_ = svc.Wait()` looks completely reasonable
// — and because the failure only appears on a machine slow enough to lose a race
// that a developer's machine wins. Nothing else would catch it before CI.
func TestEveryNebulaShutdownWaitIsBounded(t *testing.T) {
	// The only two functions allowed to call it, each of which races the wait
	// against a timer.
	allowed := map[string]string{
		filepath.Join("..", "e2e", "enroll_test.go"):       "stopNebulaOnCleanup",
		filepath.Join("..", "internal", "mesh", "node.go"): "(*Node).Close",
	}

	var offenders []string
	for _, dir := range []string{filepath.Join("..", "e2e"), filepath.Join("..", "internal", "mesh")} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			// This file names the call it is looking for, in string literals.
			if e.Name() == "shutdown_guard_test.go" {
				continue
			}
			path := filepath.Join(dir, e.Name())
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for i, line := range strings.Split(string(src), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") {
					continue
				}
				if !strings.Contains(trimmed, "svc.Wait()") {
					continue
				}
				if _, ok := allowed[path]; ok {
					continue
				}
				offenders = append(offenders, path+":"+itoa(i+1)+" "+trimmed)
			}
		}
	}

	if len(offenders) > 0 {
		t.Errorf("unbounded nebula shutdown wait:\n  %s\n\n"+
			"Wait blocks forever if nebula's teardown stalls. In a test that hangs "+
			"the whole package until the timeout; in production it hangs shutdown.\n"+
			"Use stopNebulaOnCleanup (tests) or race it against mesh.ShutdownGrace.",
			strings.Join(offenders, "\n  "))
	}

	// The allow-list must not outlive what it describes. A stale entry silently
	// re-permits exactly what this test exists to forbid.
	for path, fn := range allowed {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("allow-listed file %s is gone; update this test: %v", path, err)
		}
		if !strings.Contains(string(src), "svc.Wait()") {
			t.Errorf("%s no longer waits on nebula shutdown — drop it from the allow-list", path)
		}
		if !strings.Contains(string(src), "ShutdownGrace") {
			t.Errorf("%s waits on nebula shutdown without a bound; %s was supposed to race it against a timer", path, fn)
		}
	}
}

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
