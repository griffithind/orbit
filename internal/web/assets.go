package web

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// The asset pipeline, which is not a pipeline.
//
// Assets are content-hashed AT STARTUP and served from an immutable URL:
// /ui/static/app.<sha256[:8]>.css. That buys perfect caching — a browser holds
// the file forever and never revalidates, and a deploy that changes a byte
// changes the URL — with no build step, no manifest file, and nothing to run
// before `go build`.
//
// It is also the only correct option here rather than a nicety.
// http.ServeContent's conditional handling is driven by modification time, and
// every file in an embed.FS reports the zero time: so ServeFile on an embedded
// asset emits no useful Last-Modified, produces no ETag of its own, and answers
// every If-Modified-Since with a full body. Hashing the content is the only
// thing that can distinguish two versions of a file that both claim to be from
// the year one.
//
// The ETag is therefore set explicitly, and If-None-Match handled here. Belt and
// braces alongside the immutable URL: a proxy or an extension that ignores
// immutable still gets a 304 instead of the body.

// asset is one embedded file, ready to serve.
type asset struct {
	// path is the hashed URL path this file is served at.
	path        string
	contentType string
	etag        string
	body        []byte
}

type assets struct {
	// byPath is the serving index, keyed by the hashed path.
	byPath map[string]*asset
	// CSS and JS are the hashed paths, for the templates to reference. Named
	// fields rather than a map lookup in the template, so a renamed asset is a
	// compile error rather than an empty href discovered in a browser.
	CSS     string
	JS      string
	Favicon string
}

func loadAssets() (*assets, error) {
	as := &assets{byPath: map[string]*asset{}}

	entries, err := fs.ReadDir(assetFS, "static")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		body, err := fs.ReadFile(assetFS, "static/"+e.Name())
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])[:8]

		ext := path.Ext(e.Name())
		stem := strings.TrimSuffix(e.Name(), ext)
		a := &asset{
			path:        "/ui/static/" + stem + "." + digest + ext,
			contentType: contentTypeFor(ext),
			// A strong ETag: these bytes are the resource, byte for byte, and a
			// weak one would forbid the range requests a large asset might want
			// later for nothing gained.
			etag: `"` + digest + `"`,
			body: body,
		}
		as.byPath[a.path] = a

		switch e.Name() {
		case "app.css":
			as.CSS = a.path
		case "app.js":
			as.JS = a.path
		case "favicon.svg":
			as.Favicon = a.path
		}
	}
	return as, nil
}

// contentTypeFor maps an extension to a type.
//
// An explicit table rather than mime.TypeByExtension, which consults the host's
// /etc/mime.types and therefore returns different answers on different machines
// — including, on a minimal container image, none at all. A stylesheet served as
// application/octet-stream is a UI with no styling, and nosniff means the
// browser will not rescue it.
func contentTypeFor(ext string) string {
	switch ext {
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "text/javascript; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	default:
		return "application/octet-stream"
	}
}

func (a *assets) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, ok := a.byPath[r.URL.Path]
		if !ok {
			// A request for a path with a stale hash. 404 rather than serving the
			// current file under the old name: the old name promised immutability,
			// and answering it with different bytes would break that promise for
			// every cache between here and the browser.
			http.NotFound(w, r)
			return
		}

		h := w.Header()
		h.Set("Content-Type", f.contentType)
		h.Set("ETag", f.etag)
		// The URL contains the content hash, so these bytes can never change.
		// A year is the maximum any cache honours.
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
		h.Set("X-Content-Type-Options", "nosniff")

		if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, f.etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		// Zero time, which tells ServeContent not to emit Last-Modified or to do
		// its own (useless, see above) conditional handling. It still gets us
		// Content-Length and range support.
		http.ServeContent(w, r, "", time.Time{}, strings.NewReader(string(f.body)))
	})
}

// etagMatches implements the If-None-Match comparison for our single-value case.
func etagMatches(header, etag string) bool {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "*" || part == etag {
			return true
		}
		// A cache is permitted to weaken a strong validator.
		if strings.TrimPrefix(part, "W/") == etag {
			return true
		}
	}
	return false
}
