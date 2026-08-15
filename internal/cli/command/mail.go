package command

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/api"
)

// Notification email, through the API.

// Mail dispatches `cardinal mail`.
func Mail(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal mail <settings|set|test|status|templates>",
			cli.ErrUsage)
	}

	switch args[0] {
	case "settings":
		return mailSettings(ctx, server, flow, args[1:])
	case "set":
		return mailSet(ctx, server, flow, args[1:])
	case "test":
		return mailTest(ctx, server, flow, args[1:])
	case "status":
		return mailStatus(ctx, server, flow, args[1:])
	case "templates":
		return mailTemplates(ctx, server, flow, args[1:])
	default:
		return fmt.Errorf("%w: cardinal mail <settings|set|test|status|templates>",
			cli.ErrUsage)
	}
}

// or is the value, or a word for its absence. A blank column reads as a
// rendering fault rather than as "nothing is configured here".
func or(value, absent string) string {
	if value == "" {
		return absent
	}
	return value
}

func mailSettings(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("mail settings", flag.ContinueOnError)
	if _, err := parse(fs, args); err != nil {
		return cli.ErrUsage
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}
	m, err := client.MailSettings(ctx)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "enabled\t%t\n", m.Enabled)               //nolint:errcheck // writing to stdout; nothing actionable remains
	fmt.Fprintf(w, "host\t%s\n", or(m.Host, "not set"))      //nolint:errcheck // as above
	fmt.Fprintf(w, "port\t%d\n", m.Port)                     //nolint:errcheck // as above
	fmt.Fprintf(w, "tls\t%s\n", m.TLSMode)                   //nolint:errcheck // as above
	fmt.Fprintf(w, "username\t%s\n", or(m.Username, "none")) //nolint:errcheck // as above
	// Whether, never what. Three states rather than two: a relay with a
	// username and no stored password is a misconfiguration that used to read
	// as "set", which sent whoever was debugging a refused authentication to
	// look anywhere but at the missing secret.
	fmt.Fprintf(w, "password\t%s\n", passwordState(m))         //nolint:errcheck // as above
	fmt.Fprintf(w, "from\t%s\n", or(m.FromAddress, "not set")) //nolint:errcheck // as above
	fmt.Fprintf(w, "from name\t%s\n", or(m.FromName, "none"))  //nolint:errcheck // as above
	fmt.Fprintf(w, "reply-to\t%s\n", or(m.ReplyTo, "none"))    //nolint:errcheck // as above
	return w.Flush()
}

func passwordState(m api.MailSettings) string {
	switch {
	case m.PasswordSet:
		return "set"
	case m.Username == "":
		return "not needed"
	default:
		return "MISSING — a username is configured and no password is stored"
	}
}

func mailSet(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("mail set", flag.ContinueOnError)
	host := fs.String("host", "", "relay hostname")
	port := fs.Int("port", 587, "relay port")
	username := fs.String("username", "", "relay username, if it needs one")
	password := fs.String("password", "", "relay password; unchanged when omitted")
	from := fs.String("from", "", "address messages come from")
	fromName := fs.String("from-name", "", "display name for that address")
	replyTo := fs.String("reply-to", "", "where a reply should go")
	tlsMode := fs.String("tls", "starttls", "starttls, tls or none")
	enable := fs.Bool("enable", false, "start sending")
	disable := fs.Bool("disable", false, "stop sending")
	if _, err := parse(fs, args); err != nil {
		return cli.ErrUsage
	}
	if *enable && *disable {
		return fmt.Errorf("%w: -enable and -disable disagree", cli.ErrUsage)
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}

	// Read first, so a command that sets one field leaves the rest alone. The
	// endpoint replaces the settings whole, which is right for the console's
	// form and wrong for a command naming one flag — so the merge happens here.
	//
	// Two callers editing at the same instant would have the later one win with
	// the earlier one's values. Said rather than guarded: this is one operator
	// at a terminal, and a lock on a settings row would be machinery for a race
	// nobody is running.
	current, err := client.MailSettings(ctx)
	if err != nil {
		return err
	}

	// Which flags were actually typed, rather than which differ from a default.
	//
	// The two are not the same and the difference is a bug somebody hits once
	// and then distrusts the command forever: `-tls` defaults to "starttls", so
	// treating a non-empty value as "given" made `mail set -username relay-user`
	// silently move a working relay off `none` and back onto STARTTLS.
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })

	next := api.MailSettingsRequest{
		Enabled:     current.Enabled,
		Host:        current.Host,
		Port:        current.Port,
		Username:    current.Username,
		FromAddress: current.FromAddress,
		FromName:    current.FromName,
		ReplyTo:     current.ReplyTo,
		TLSMode:     current.TLSMode,
		Password:    *password, // empty leaves the stored one alone
	}
	if given["host"] {
		next.Host = *host
	}
	if given["port"] {
		next.Port = *port
	}
	if given["username"] {
		next.Username = *username
	}
	if given["from"] {
		next.FromAddress = *from
	}
	if given["from-name"] {
		next.FromName = *fromName
	}
	if given["reply-to"] {
		next.ReplyTo = *replyTo
	}
	if given["tls"] {
		next.TLSMode = *tlsMode
	}

	// A first configuration has no port yet, and 587 is the sensible one. The
	// endpoint refuses zero, so this is the difference between a working first
	// run and an error about a field nobody mentioned.
	if next.Port == 0 {
		next.Port = *port
	}
	if next.TLSMode == "" {
		next.TLSMode = *tlsMode
	}
	if *enable {
		next.Enabled = true
	}
	if *disable {
		next.Enabled = false
	}

	if err := client.SaveMailSettings(ctx, next); err != nil {
		return err
	}
	fmt.Println("saved")
	if next.Enabled && next.Host == "" {
		fmt.Fprintln(os.Stderr,
			"  Note: enabled with no relay host, so nothing will be sent.")
	}
	if next.Username != "" && *password == "" && !current.PasswordSet {
		fmt.Fprintln(os.Stderr,
			"  Note: a username is configured and no password is stored, so the\n"+
				"  relay will refuse the connection. Pass -password to set one.")
	}
	return nil
}

func mailTest(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("mail test", flag.ContinueOnError)
	to := fs.String("to", "", "where to send it (required)")
	if _, err := parse(fs, args); err != nil {
		return cli.ErrUsage
	}
	if *to == "" {
		return fmt.Errorf("%w: cardinal mail test -to <address>", cli.ErrUsage)
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}

	// Said before sending, because when it fails this is the line that tells
	// somebody which relay refused them.
	if settings, settingsErr := client.MailSettings(ctx); settingsErr == nil {
		fmt.Fprintf(os.Stderr, "  sending through %s:%d as %s\n",
			settings.Host, settings.Port, settings.FromAddress)
	}

	result, err := client.SendTestMail(ctx, *to)
	if err != nil {
		return err
	}
	// A refusal arrives as a successful request reporting an unsuccessful send,
	// so the status code is not the answer. Reporting only the transport would
	// print "sent" for a message the relay rejected.
	if !result.Sent {
		return fmt.Errorf("the relay refused it: %s", result.Error)
	}

	fmt.Printf("sent to %s\n", *to)
	return nil
}

func mailStatus(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("mail status", flag.ContinueOnError)
	if _, err := parse(fs, args); err != nil {
		return cli.ErrUsage
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}
	m, err := client.MailSettings(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("%d queued", m.Queued)
	if m.Failing > 0 {
		// Named separately because "queued" and "queued and failing" are
		// different situations, and a count that merges them looks healthy
		// right up until nothing has arrived for a week.
		fmt.Printf(", %d of them failing after more than three attempts", m.Failing)
	}
	fmt.Println()
	return nil
}

func mailTemplates(ctx context.Context, server string, flow cli.AuthFlow, args []string) error {
	fs := flag.NewFlagSet("mail templates", flag.ContinueOnError)
	show := fs.String("show", "", "print one template's current wording")
	reset := fs.String("reset", "", "discard an override, returning to the built-in")
	if _, err := parse(fs, args); err != nil {
		return cli.ErrUsage
	}

	client, err := cli.Client(ctx, server, flow)
	if err != nil {
		return err
	}

	if *reset != "" {
		if resetErr := client.ResetMailTemplate(ctx, *reset); resetErr != nil {
			return resetErr
		}
		fmt.Printf("%s is back to the built-in wording\n", *reset)
		return nil
	}

	templates, err := client.MailTemplates(ctx)
	if err != nil {
		return err
	}

	if *show != "" {
		for _, t := range templates {
			if t.Kind != *show {
				continue
			}
			source := "built-in"
			if t.Overridden {
				source = "overridden"
			}
			fmt.Printf("# %s (%s)\n\nSubject: %s\n\n%s\n", t.Kind, source, t.Subject, t.Body)
			return nil
		}
		return fmt.Errorf("no such message: %s", *show)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "MESSAGE\tWORDING") //nolint:errcheck // writing to stdout; nothing actionable remains
	for _, t := range templates {
		source := "built-in"
		if t.Overridden {
			source = "overridden"
		}
		fmt.Fprintf(w, "%s\t%s\n", t.Kind, source) //nolint:errcheck // as above
	}
	return w.Flush()
}
