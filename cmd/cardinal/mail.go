package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/cli/direct"
	"go.londer.be/cardinal/internal/server/mail"
	"go.londer.be/cardinal/internal/store"
)

// Configuring notification email from a terminal.
//
// Here as well as in the console because the deployment most likely to need it
// is one nobody can sign into yet: mail is often set up before the first person
// has a passkey, and a settings page you cannot reach is no use.
func runMail(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: cardinal mail <settings|set|test|status|templates>", errUsage)
	}
	switch args[0] {
	case "settings":
		return runMailSettings(ctx, args[1:])
	case "set":
		return runMailSet(ctx, args[1:])
	case "test":
		return runMailTest(ctx, args[1:])
	case "status":
		return runMailStatus(ctx, args[1:])
	case "templates":
		return runMailTemplates(ctx, args[1:])
	default:
		return fmt.Errorf("%w: cardinal mail <settings|set|test|status|templates>", errUsage)
	}
}

func runMailSettings(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mail settings", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}
	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	m, err := s.MailSettings(ctx)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "enabled\t%t\n", m.Enabled)               //nolint:errcheck // the header is already written, so the status cannot be changed
	fmt.Fprintf(w, "host\t%s\n", or(m.Host, "not set"))      //nolint:errcheck // as above
	fmt.Fprintf(w, "port\t%d\n", m.Port)                     //nolint:errcheck // as above
	fmt.Fprintf(w, "tls\t%s\n", m.TLSMode)                   //nolint:errcheck // as above
	fmt.Fprintf(w, "username\t%s\n", or(m.Username, "none")) //nolint:errcheck // as above
	// Whether, never what. The value is sealed in the database and there is no
	// question a settings listing answers by printing a relay password.
	fmt.Fprintf(w, "password\t%s\n", secretState(m))           //nolint:errcheck // as above
	fmt.Fprintf(w, "from\t%s\n", or(m.FromAddress, "not set")) //nolint:errcheck // as above
	fmt.Fprintf(w, "from name\t%s\n", or(m.FromName, "none"))  //nolint:errcheck // as above
	fmt.Fprintf(w, "reply-to\t%s\n", or(m.ReplyTo, "none"))    //nolint:errcheck // as above
	return w.Flush()
}

func runMailSet(ctx context.Context, args []string) error {
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
	configPath := fs.String("config", "", "configuration file, for the encryption key")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}
	if *enable && *disable {
		return fmt.Errorf("%w: -enable and -disable disagree", errUsage)
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	// Read first, so a command that sets one field leaves the rest alone. A
	// settings command that silently blanked everything not mentioned would be
	// a trap somebody falls into once and then never trusts again.
	current, err := s.MailSettings(ctx)
	if err != nil {
		return err
	}

	// Which flags were actually typed, rather than which differ from a default.
	//
	// The two are not the same and the difference is a bug somebody hits once
	// and then distrusts the command forever: `-tls` defaults to "starttls", so
	// treating a non-empty value as "given" made `mail set -username relay-user`
	// silently move a working relay off `none` and back onto STARTTLS. Found by
	// running it — the send then failed with "the relay does not offer STARTTLS",
	// which was true and about a setting nobody had touched.
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })

	next := *current
	if given["host"] {
		next.Host = *host
	}
	if given["port"] {
		next.Port = *port
	}
	if given["username"] {
		next.Username = *username
	}
	next.Password = *password // empty leaves the stored one alone
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

	// A first configuration has no port yet, and 587 is the sensible one.
	if next.Port == 0 {
		next.Port = *port
	}
	if *enable {
		next.Enabled = true
	}
	if *disable {
		next.Enabled = false
	}

	sealKey, err := mailSealKey(*configPath)
	if err != nil && *password != "" {
		return err
	}

	if err := s.SaveMailSettings(ctx, next, sealKey, nil); err != nil {
		return err
	}
	fmt.Println("saved")
	if next.Enabled && next.Host == "" {
		fmt.Fprintln(os.Stderr,
			"  Note: enabled with no relay host, so nothing will be sent.")
	}
	return nil
}

// runMailTest sends one message and says exactly what the relay said.
//
// The command that makes SMTP debuggable. Every failure mode here — a name that
// does not resolve, a certificate nobody trusts, credentials the relay rejects,
// a sender it will not accept — produces a different sentence, and guessing
// between them from "notifications are not arriving" is hours.
func runMailTest(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mail test", flag.ContinueOnError)
	to := fs.String("to", "", "where to send it (required)")
	configPath := fs.String("config", "", "configuration file, for the encryption key")
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}
	if *to == "" {
		return fmt.Errorf("%w: cardinal mail test -to <address>", errUsage)
	}

	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	sealKey, err := mailSealKey(*configPath)
	if err != nil {
		return err
	}
	settings, err := s.MailSettingsWithPassword(ctx, sealKey)
	if err != nil {
		return err
	}
	if settings.Host == "" {
		return store.ErrMailNotConfigured
	}

	// The same product name and console URL the server uses, so what arrives
	// looks like what a real notification will. A test that said "Cardinal"
	// while every other message said the deployment's own name would prove the
	// relay works and nothing about the messages.
	data := mail.Data{Login: "(test)", When: time.Now().Format(time.RFC1123)}
	if cfg, cfgErr := direct.LoadConfig(*configPath); cfgErr == nil {
		data.Product = cfg.WebAuthn.RPDisplayName
		data.ConsoleURL = cfg.Server.PublicURL
	}

	subject, body, err := mail.Render(mail.KindTest, nil, data)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "  sending through %s:%d as %s\n",
		settings.Host, settings.Port, settings.FromAddress)

	// Sent directly rather than queued, because the point is to see the answer
	// now. A test that joined the outbox would report "queued" and leave
	// somebody watching a log.
	err = mail.Send(ctx, mail.Relay{
		Host: settings.Host, Port: settings.Port,
		Username: settings.Username, Password: settings.Password,
		FromAddress: settings.FromAddress, FromName: settings.FromName,
		ReplyTo: settings.ReplyTo, TLSMode: settings.TLSMode,
	}, mail.Message{To: *to, Subject: subject, Body: body})
	if err != nil {
		return err
	}
	fmt.Printf("sent to %s\n", *to)
	return nil
}

func runMailStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mail status", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}
	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	pending, failing, err := s.PendingMail(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("%d queued", pending)
	if failing > 0 {
		// Named separately because "queued" and "queued and failing" are
		// different situations, and a count that merges them looks healthy
		// right up until nothing has arrived for a week.
		fmt.Printf(", %d of them failing after more than three attempts", failing)
	}
	fmt.Println()
	return nil
}

func runMailTemplates(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mail templates", flag.ContinueOnError)
	dsnFlag := fs.String("dsn", "", "PostgreSQL connection string")
	show := fs.String("show", "", "print one template's current wording")
	reset := fs.String("reset", "", "discard an override, returning to the built-in")
	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}
	s, err := direct.Open(ctx, *dsnFlag)
	if err != nil {
		return err
	}
	defer s.Close()

	overrides, err := s.MailTemplates(ctx)
	if err != nil {
		return err
	}

	if *reset != "" {
		if err := s.ResetMailTemplate(ctx, *reset); err != nil {
			return err
		}
		fmt.Printf("%s is back to the built-in wording\n", *reset)
		return nil
	}

	if *show != "" {
		builtin, ok := mail.Builtin(mail.Kind(*show))
		if !ok {
			return fmt.Errorf("no such message: %s", *show)
		}
		t := builtin
		source := "built-in"
		if o, edited := overrides[*show]; edited {
			t = mail.Template{Subject: o.Subject, Body: o.Body}
			source = "overridden"
		}
		fmt.Printf("# %s (%s)\n\nSubject: %s\n\n%s\n", *show, source, t.Subject, t.Body)
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "MESSAGE\tWORDING") //nolint:errcheck // the header is already written, so the status cannot be changed
	for _, kind := range mail.Kinds() {
		source := "built-in"
		if _, edited := overrides[string(kind)]; edited {
			source = "overridden"
		}
		fmt.Fprintf(w, "%s\t%s\n", kind, source) //nolint:errcheck // as above
	}
	return w.Flush()
}

// mailSealKey reads the key that protects the relay password.
func mailSealKey(configPath string) (string, error) {
	cfg, err := direct.LoadConfig(configPath)
	if err != nil {
		return "", fmt.Errorf("reading the configuration for mail.encryption_key: %w", err)
	}
	if strings.TrimSpace(cfg.Mail.EncryptionKey) == "" {
		return "", errors.New(
			"mail.encryption_key is not set, so a relay password cannot be stored.\n\n" +
				"  Generate one with `openssl rand -base64 32` and put it in the [mail]\n" +
				"  section. It stays in the file for the same reason the certificate\n" +
				"  authorities' keys do: it protects a credential in the database")
	}
	return cfg.Mail.EncryptionKey, nil
}

func or(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func secretState(m *store.MailSettings) string {
	if m.Username == "" {
		return "not needed"
	}
	return "set"
}
