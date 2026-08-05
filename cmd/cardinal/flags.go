package main

import (
	"flag"
	"strings"
)

// parse is flag.FlagSet.Parse with argument permutation, returning the
// positional arguments.
//
// Go's flag package stops parsing at the first non-flag argument, so
// `cardinal user create alice -display "Arthur"` would silently treat
// `-display` and its value as positionals and never set the flag. That is a
// genuinely nasty failure mode — the command appears to succeed while quietly
// dropping input — so flags are hoisted ahead of positionals first, matching
// what every GNU-style CLI does.
//
// Everything after a bare "--" is positional, per convention.
func parse(fs *flag.FlagSet, argv []string) ([]string, error) {
	flags, positional := permute(fs, argv)
	if err := fs.Parse(flags); err != nil {
		return nil, err
	}
	return positional, nil
}

// permute splits argv into flag arguments and positional ones.
//
// Deciding whether a flag consumes the following argument requires knowing
// whether it is boolean: `-all next` is `-all` plus positional `next`, whereas
// `-reason next` is `-reason=next`. The FlagSet knows, via the IsBoolFlag
// convention.
func permute(fs *flag.FlagSet, argv []string) (flags, positional []string) {
	for i := 0; i < len(argv); i++ {
		a := argv[i]

		if a == "--" {
			positional = append(positional, argv[i+1:]...)
			return flags, positional
		}

		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}

		flags = append(flags, a)

		// -name=value carries its own value.
		if strings.Contains(a, "=") {
			continue
		}

		if isBool(fs, strings.TrimLeft(a, "-")) {
			continue
		}
		// Non-boolean flag: the next argument is its value.
		if i+1 < len(argv) {
			i++
			flags = append(flags, argv[i])
		}
	}
	return flags, positional
}

// isBool reports whether the named flag is boolean, and so does not consume the
// next argument. Unknown flags are treated as non-boolean so their value is
// passed through and flag.Parse can report a proper error.
func isBool(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && bf.IsBoolFlag()
}
