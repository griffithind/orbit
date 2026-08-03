// Package version holds the one build version string for every Orbit binary.
//
// There were briefly two — a const in internal/agent and a var in internal/api —
// which is the number that guarantees they disagree. An agent reporting one
// version while the control plane's /healthz reports another is exactly the
// confusion a version string exists to prevent, and nothing would have caught
// it: both compile, both look right in isolation.
//
// Set at build time:
//
//	go build -ldflags "-X github.com/griffithind/orbit/internal/version.Version=$(VERSION)" ./...
//
// The default is "dev" rather than the empty string on purpose. An empty value
// combined with an omitempty tag disappears from a response entirely, making a
// failed injection indistinguishable from an old binary that had no version
// field at all. "dev" is always visible and is never a release.
package version

// Version is the build version. Overridden via -ldflags; see the package doc.
var Version = "dev"
