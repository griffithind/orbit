package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
)

// Shell completion.
//
// ADR-0004 keeps this CLI on stdlib flag, and named completion as the one thing
// a framework would have given us. This is that thing, and it is about ninety
// lines rather than the two-to-five modules cobra, urfave or kong would have
// added to a binary that ships to every managed host.
//
// The shell scripts are written here rather than vendored from cobra. Tailscale
// vendored cobra's — they are Apache-2.0 and that is a legitimate route — but
// cobra's scripts carry a directive protocol this tree does not implement, and a
// copy of someone else's code whose features you do not use is a maintenance
// cost pretending to be a shortcut.
//
// The contract is one hidden command: `orbit __complete <words...>` prints one
// candidate per line for the position after those words. Everything shell-side
// is a call to it, which keeps the logic in Go where the command tree already
// lives and means a new command is completable the moment it is in the table.

// completeCmd emits candidates for the position after args.
func completeCmd(_ context.Context, args []string) error {
	node := rootCommand()
	partial := ""

	// The last word is what is being typed unless it is already complete, which
	// the shell signals by passing an empty final word.
	if len(args) > 0 && !strings.HasSuffix(args[len(args)-1], " ") {
		partial = args[len(args)-1]
		args = args[:len(args)-1]
	}

	// Walk as far into the tree as the completed words go. An unknown word
	// means the line is not completable, and offering the root's verbs there
	// would be actively misleading.
	for _, w := range args {
		if strings.HasPrefix(w, "-") {
			continue
		}
		next := node.find(w)
		if next == nil {
			return nil
		}
		node = next
	}

	// A flag is being typed: offer this command's own flags. Leaves still
	// define theirs inside their functions, so the set is discovered by
	// building the FlagSet the same way dispatch would.
	if strings.HasPrefix(partial, "-") {
		fs := flag.NewFlagSet("complete", flag.ContinueOnError)
		if node.Flags != nil {
			node.Flags(fs)
		}
		var names []string
		fs.VisitAll(func(f *flag.Flag) { names = append(names, "--"+f.Name) })
		// The common set every admin command carries. Named here because
		// options.bind is what registers them and it is not reachable without
		// running the command.
		names = append(names, "--url", "--token-file", "--network", "--profile", "--json", "--yes")
		emitMatching(names, partial)
		return nil
	}

	var names []string
	for _, s := range node.Subs {
		if !s.Hidden {
			names = append(names, s.Name)
		}
	}
	emitMatching(names, partial)
	return nil
}

func emitMatching(candidates []string, partial string) {
	for _, c := range candidates {
		if strings.HasPrefix(c, partial) {
			fmt.Fprintln(out, c)
		}
	}
}

func completionCmd(_ context.Context, args []string) error {
	if len(args) != 1 {
		return usageErrorf("usage: orbit completion <bash|zsh|fish>\n\n" +
			"  orbit completion bash > /etc/bash_completion.d/orbit\n" +
			"  orbit completion zsh  > \"${fpath[1]}/_orbit\"\n" +
			"  orbit completion fish > ~/.config/fish/completions/orbit.fish")
	}
	switch args[0] {
	case "bash":
		fmt.Fprint(out, bashCompletion)
	case "zsh":
		fmt.Fprint(out, zshCompletion)
	case "fish":
		fmt.Fprint(out, fishCompletion)
	default:
		return usageErrorf("unknown shell %q; orbit completes bash, zsh and fish", args[0])
	}
	return nil
}

// Each script does the same three things: take the words before the cursor, ask
// the binary, and offer what it says. No caching and no client-side filtering —
// __complete already filters on the partial word, and a shell-side copy of that
// logic is a second implementation that would drift.

const bashCompletion = `# bash completion for orbit
_orbit_complete() {
    local IFS=$'\n'
    # COMP_WORDS[0] is the binary; everything after it up to the cursor is what
    # __complete needs. The current word is passed even when empty, because an
    # empty final word is how the binary is told the previous one is finished.
    COMPREPLY=( $(orbit __complete "${COMP_WORDS[@]:1:COMP_CWORD}" 2>/dev/null) )
}
complete -o default -F _orbit_complete orbit
`

const zshCompletion = `#compdef orbit
# zsh completion for orbit
_orbit() {
    local -a candidates
    # ${words[2,CURRENT]} drops the binary name and keeps everything up to and
    # including the word under the cursor.
    candidates=( ${(f)"$(orbit __complete ${words[2,CURRENT]} 2>/dev/null)"} )
    if (( ${#candidates} )); then
        compadd -a candidates
    else
        _files
    fi
}
compdef _orbit orbit
`

const fishCompletion = `# fish completion for orbit
function __orbit_complete
    set -l tokens (commandline -opc) (commandline -ct)
    orbit __complete $tokens[2..-1] 2>/dev/null
end
complete -c orbit -f -a '(__orbit_complete)'
`
