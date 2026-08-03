// Package version holds the one build version string for every Orbit binary.
//
// One, and it has to stay one. A second version string somewhere else compiles,
// looks right in isolation, and produces an agent reporting one version while
// the control plane's /healthz reports another — exactly the confusion a
// version string exists to prevent, and nothing catches it.
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
