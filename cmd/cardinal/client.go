package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.londer.be/cardinal/internal/cli"
)

// client runs a command that reaches Cardinal's API.
//
// It exists so a client command never has to think about where the server is or
// whether it is signed in.
//
// The `-dsn` check below is a message rather than a barrier, and it is worth
// being accurate about which. Removing it does not open a database path:
// nothing downstream declares that flag, so the command's own parser refuses it
// anyway — measured, and what it prints instead is the word "usage". The check
// turns that into a sentence naming the six commands that do take `-dsn`, which
// is the difference between a person learning the rule and guessing at it.
func client(ctx context.Context, args []string, run func(context.Context, string, cli.AuthFlow, []string) error) error {
	// -server and -auth are read here and removed, so each command's own
	// FlagSet does not have to declare them and cannot disagree about a name.
	server, rest, err := serverFlag(args)
	if err != nil {
		return err
	}
	flowName, rest, err := valueFlag(rest, "auth")
	if err != nil {
		return err
	}
	flow, err := cli.ParseAuthFlow(flowName)
	if err != nil {
		return err
	}

	base, err := serverURL(server)
	if err != nil {
		return err
	}
	return run(ctx, base, flow, rest)
}

// valueFlag pulls `-name value` out of the arguments wherever it appears.
func valueFlag(args []string, name string) (value string, rest []string, err error) {
	for i := range args {
		switch {
		case args[i] == "-"+name || args[i] == "--"+name:
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("%w: -%s needs a value", cli.ErrUsage, name)
			}
			rest = append(rest, args[:i]...)
			rest = append(rest, args[i+2:]...)
			return args[i+1], rest, nil
		case strings.HasPrefix(args[i], "-"+name+"="),
			strings.HasPrefix(args[i], "--"+name+"="):
			rest = append(rest, args[:i]...)
			rest = append(rest, args[i+1:]...)
			return args[i][strings.Index(args[i], "=")+1:], rest, nil
		}
	}
	return "", args, nil
}

// serverFlag pulls -server out of the arguments wherever it appears.
func serverFlag(args []string) (server string, rest []string, err error) {
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-dsn" || args[i] == "--dsn" ||
			strings.HasPrefix(args[i], "-dsn=") || strings.HasPrefix(args[i], "--dsn="):
			return "", nil, errors.New(
				"this command signs in rather than opening the database.\n" +
					"  Point it at a server with -server, or set CARDINAL_SERVER.\n" +
					"  The commands that still take -dsn are the ones that have to work " +
					"when nobody can sign in: migrate, init, invite, policy activate, " +
					"decisions and redact")
		case args[i] == "-server" || args[i] == "--server":
			if i+1 >= len(args) {
				return "", nil, errors.New("-server needs a URL")
			}
			server = args[i+1]
			rest = append(rest, args[:i]...)
			rest = append(rest, args[i+2:]...)
			return server, rest, nil
		case strings.HasPrefix(args[i], "-server="), strings.HasPrefix(args[i], "--server="):
			server = args[i][strings.Index(args[i], "=")+1:]
			rest = append(rest, args[:i]...)
			rest = append(rest, args[i+1:]...)
			return server, rest, nil
		}
	}
	return "", args, nil
}
