package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"go.londer.be/cardinal/internal/cli"
	"go.londer.be/cardinal/internal/config"
)

// runConfig prints the effective configuration.
//
// The same report the console renders, from the machine the server runs on and
// without the server running. Its value is the Source column: a setting nobody
// chose still has a value, and "where did this come from" is unanswerable from
// the file alone once environment variables and defaults are in play.
func runConfig(_ context.Context, args []string) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	configPath := fs.String("config", "", "configuration file")
	all := fs.Bool("all", false, "include settings left at their default")

	if _, err := cli.Parse(fs, args); err != nil {
		return errUsage
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SETTING\tVALUE\tSOURCE") //nolint:errcheck // the header is already written, so the status cannot be changed

	var ignored []config.Setting
	for _, setting := range cfg.Report() {
		if setting.Ignored != "" {
			ignored = append(ignored, setting)
			continue
		}
		if !*all && setting.Source == "default" {
			continue
		}
		fmt.Fprintf(w, "%s.%s\t%s\t%s\n", //nolint:errcheck // the header is already written, so the status cannot be changed
			setting.Section, setting.Name, setting.Value, setting.Source)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	// Last and unconditionally, because this is the part somebody needs to see.
	// A setting that is parsed and validated and then read by nothing looks
	// supported, so somebody tunes it and believes the tuning took effect.
	if len(ignored) > 0 {
		fmt.Println()
		fmt.Printf("%d setting(s) are accepted but not used:\n", len(ignored))
		for _, setting := range ignored {
			fmt.Printf("  %s.%s — %s\n", setting.Section, setting.Name, setting.Ignored)
		}
	}
	if !*all {
		fmt.Println()
		fmt.Println("  Settings left at their default are hidden; -all shows them.")
	}
	return nil
}
