package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"go.yaml.in/yaml/v3"

	"github.com/griffithind/orbit/internal/adminclient"
	"github.com/griffithind/orbit/internal/wire"
)

// options are the flags every subcommand accepts.
//
// Registered per subcommand rather than parsed before the verb, so flags come
// after it: `orbit membership ls -network prod`, matching `orbitd serve -addr` and
// `orbit agent run -dir`. Go's flag package accepts both -network and --network,
// so the CLI is forgiving in the direction people actually expect while the
// product still speaks one dialect.
type options struct {
	url       string
	tokenFile string
	network   string
	profile   string
	json      bool
	yes       bool

	// Resolved during load.
	profileName string
	token       string

	client *adminclient.Client
	r      renderer
}

// bind registers the common flags on a subcommand's flag set.
//
// There is no -token. A token on the command line is visible in ps to every
// other user on the machine and lands in shell history;
// scripts/check-break-glass.sh states exactly this and passes its own credential
// through the environment for the same reason. Offering the flag "for
// convenience" would mean every example that copies it teaches the unsafe form.
func (o *options) bind(fs *flag.FlagSet) {
	fs.StringVar(&o.url, "url", "", "control plane admin URL (or ORBIT_URL)")
	fs.StringVar(&o.tokenFile, "token-file", "", "file holding the admin token (or ORBIT_TOKEN_FILE, ORBIT_TOKEN)")
	fs.StringVar(&o.network, "network", "", "network name or uuid (or ORBIT_NETWORK)")
	fs.StringVar(&o.profile, "profile", "", "profile in ~/.config/orbit/config.yaml (or $ORBIT_CONFIG)")
	fs.BoolVar(&o.json, "json", false, "emit the API response verbatim")
	fs.BoolVar(&o.yes, "y", false, "skip confirmation prompts")
}

//------------------------------------------------------------------------------
// Profiles
//------------------------------------------------------------------------------

// configFile is what ~/.config/orbit/config.yaml holds.
type configFile struct {
	DefaultProfile string             `yaml:"default_profile"`
	Profiles       map[string]profile `yaml:"profiles"`
}

type profile struct {
	URL       string `yaml:"url"`
	Network   string `yaml:"network"`
	TokenFile string `yaml:"token_file"`

	// Token is declared only so it can be refused.
	//
	// There is no inline token key, deliberately. Config files end up in dotfiles
	// repositories, in configuration management, and in support bundles; a path
	// to a token is not a token, and it survives all three harmlessly. Declaring
	// the field means an operator who tries gets an explanation rather than a
	// silently ignored line and a CLI that inexplicably has no credential.
	Token string `yaml:"token"`
}

func configPath() string {
	if v := os.Getenv("ORBIT_CONFIG"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "orbit", "config.yaml")
}

// loadProfile reads the named profile, or the default one. A missing config file
// is not an error: the zero-configuration path — ORBIT_URL and ORBIT_TOKEN,
// exactly what `orbitd bootstrap` prints — must work without one.
func loadProfile(name string) (profile, string, error) {
	path := configPath()
	if path == "" {
		return profile{}, "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if name != "" {
				return profile{}, "", usageErrorf("-profile %s was requested but %s does not exist", name, path)
			}
			return profile{}, "", nil
		}
		return profile{}, "", fmt.Errorf("read %s: %w", path, err)
	}

	var cf configFile
	if err := yaml.Unmarshal(raw, &cf); err != nil {
		return profile{}, "", fmt.Errorf("parse %s: %w", path, err)
	}

	if name == "" {
		name = cf.DefaultProfile
	}
	if name == "" {
		return profile{}, "", nil
	}
	p, ok := cf.Profiles[name]
	if !ok {
		return profile{}, "", usageErrorf("no profile %q in %s (have: %s)",
			name, path, strings.Join(profileNames(cf), ", "))
	}
	if p.Token != "" {
		return profile{}, "", usageErrorf(
			"profile %q in %s sets `token:`, which orbit will not read.\n\n"+
				"Use `token_file:` and point it at a file holding the token. A config file "+
				"ends up in dotfiles repositories and support bundles; a path to a token is "+
				"not a token.", name, path)
	}
	return p, name, nil
}

func profileNames(cf configFile) []string {
	out := make([]string, 0, len(cf.Profiles))
	for k := range cf.Profiles {
		out = append(out, k)
	}
	return out
}

//------------------------------------------------------------------------------
// Token
//------------------------------------------------------------------------------

// loadToken resolves the credential, most explicit source first.
//
// -token-file, ORBIT_TOKEN_FILE, ORBIT_TOKEN, then the profile's token_file. The
// environment variable holding the value itself sits below both file forms and
// above the profile: it is what `orbitd bootstrap` tells an operator to export,
// so it has to work, but a file is the form that survives being in a process
// listing and a shell history.
func loadToken(flagPath string, p profile) (string, error) {
	if flagPath != "" {
		return readTokenFile(flagPath, "-token-file")
	}
	if v := os.Getenv("ORBIT_TOKEN_FILE"); v != "" {
		return readTokenFile(v, "ORBIT_TOKEN_FILE")
	}
	if v := os.Getenv("ORBIT_TOKEN"); v != "" {
		return strings.TrimSpace(v), nil
	}
	if p.TokenFile != "" {
		return readTokenFile(expandHome(p.TokenFile), "token_file")
	}
	return "", usageErrorf(
		"no admin token.\n\n" +
			"  export ORBIT_TOKEN=…            what `orbitd bootstrap` prints\n" +
			"  export ORBIT_TOKEN_FILE=path    or point at a file holding it\n" +
			"  orbit … -token-file path        or pass the path per invocation\n\n" +
			"There is deliberately no -token flag: an argument is visible in ps to every " +
			"user on the box.")
}

func readTokenFile(path, source string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", usageErrorf("%s: %v", source, err)
	}
	// Warn rather than refuse, mirroring ca.NewFileSignerFromPath's check but not
	// its severity. That one guards a mesh-wide root key and refuses; this one
	// guards a token that is scoped, revocable, and often expiring — refusing
	// would strand an operator mid-incident over a file mode they can fix later.
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		fmt.Fprintf(errOut, "orbit: warning: %s is mode %04o, want 0600 (chmod 600 %s)\n",
			path, mode, path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return "", usageErrorf("%s: %v", source, err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", usageErrorf("%s: %s is empty", source, path)
	}
	return tok, nil
}

func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}

//------------------------------------------------------------------------------
// Loading
//------------------------------------------------------------------------------

// load resolves the URL, the credential, and the profile, and builds a client.
func (o *options) load() error {
	p, name, err := loadProfile(o.profile)
	if err != nil {
		return err
	}
	o.profileName = name

	if o.url == "" {
		o.url = os.Getenv("ORBIT_URL")
	}
	if o.url == "" {
		o.url = p.URL
	}
	if o.url == "" {
		return usageErrorf(
			"no control plane URL.\n\n"+
				"  export ORBIT_URL=http://localhost:8080\n"+
				"  orbit … -url http://localhost:8080\n"+
				"  or set `url:` in a profile in %s", configPath())
	}
	if !strings.Contains(o.url, "://") {
		// A bare host is a common paste, and http:// is not a safe guess to make
		// silently for a credential-bearing request.
		return usageErrorf("-url %q has no scheme; write it as http://%s or https://%s",
			o.url, o.url, o.url)
	}

	if o.network == "" {
		o.network = os.Getenv("ORBIT_NETWORK")
	}
	if o.network == "" {
		o.network = p.Network
	}

	o.token, err = loadToken(o.tokenFile, p)
	if err != nil {
		return err
	}

	o.client = adminclient.New(o.url, o.token)
	o.r = newRenderer()
	return nil
}

// resolveNetwork returns the network this invocation acts on.
//
// With nothing configured it falls back to the sole network, which makes a fresh
// `orbitd bootstrap` usable immediately — and refuses when there is more than
// one, because silently picking is the failure this CLI is designed against.
func (o *options) resolveNetwork(ctx context.Context) (*wire.NetworkResponse, error) {
	if o.network == "" {
		return o.client.SoleNetwork(ctx)
	}
	return o.client.ResolveNetwork(ctx, o.network)
}

func (o *options) networkID(ctx context.Context) (uuid.UUID, error) {
	n, err := o.resolveNetwork(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(n.ID)
}

//------------------------------------------------------------------------------
// Acting out loud
//------------------------------------------------------------------------------

// announce names the control plane and profile a mutating command is about to
// act on, before it acts.
//
// The failure being designed against is blocking a prod host while believing you
// are in staging. Two shells with different exports look identical, and the CLI
// is the only thing that knows which one this is. On stderr, so it never
// contaminates -json on stdout.
func (o *options) announce(action string) {
	fmt.Fprintf(errOut, "%s\n  url      %s\n", action, o.url)
	if o.profileName != "" {
		fmt.Fprintf(errOut, "  profile  %s\n", o.profileName)
	} else {
		fmt.Fprintf(errOut, "  profile  (none)\n")
	}
	if o.network != "" {
		fmt.Fprintf(errOut, "  network  %s\n", o.network)
	}
	fmt.Fprintln(errOut)
}

// confirm asks before an irreversible action.
//
// Only for what cannot be undone — deleting a host, retiring a CA, deleting a
// role, activating a CA past hosts that have not converged, revoking the token
// in your own hand. Blocking a host is reversible with `orbit membership unblock` and
// is deliberately not prompted: a prompt on a reversible action teaches people
// to type y without reading, which is what makes the prompt on an irreversible
// one worthless.
//
// The prompt itself appears only on a terminal, because in CI there is nobody to
// answer one. But off a terminal the action is refused rather than performed:
// consent has to come from somewhere, and -y is where. Proceeding silently would
// mean any pipeline that happened to invoke this — including one an operator
// wrote expecting the prompt they get by hand — decommissions a host with no
// confirmation anywhere in it.
func (o *options) confirm(prompt string) error {
	if o.yes {
		return nil
	}
	if !stdinIsTTY() {
		return fail(exitUsage,
			"%s\n\nNothing was done: this is an irreversible action and stdin is not a "+
				"terminal, so there is nobody to ask. Pass -y to confirm.", prompt)
	}
	fmt.Fprintf(errOut, "%s [y/N] ", prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		// A terminal that answers with EOF is one nobody is typing at, whatever
		// os.Stat said about it. Refuse rather than assume.
		return fail(exitUsage,
			"no answer on stdin, so nothing was done. Pass -y to confirm non-interactively.")
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	default:
		return fail(exitUsage, "cancelled")
	}
}

func stdinIsTTY() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
