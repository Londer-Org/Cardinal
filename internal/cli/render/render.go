// Package render turns results into something a terminal can read.
//
// Separated from the commands because output is a third job, and mixing it with
// flag parsing and transport is why adding a format touched every file in the
// old layout.
package render

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Table writes aligned columns.
func Table(w io.Writer, headers []string, rows [][]string) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if len(headers) > 0 {
		fmt.Fprintln(tw, strings.Join(headers, "\t")) //nolint:errcheck // a terminal that will not accept output is not recoverable here
	}
	for _, row := range rows {
		fmt.Fprintln(tw, strings.Join(row, "\t")) //nolint:errcheck // as above
	}
	_ = tw.Flush() //nolint:errcheck // as above
}

// Period renders a grant's validity the way the CLI has always shown it.
func Period(from fmt.Stringer, until *string) string {
	if until == nil {
		return "from " + from.String() + ", no end"
	}
	return "from " + from.String() + " until " + *until
}
