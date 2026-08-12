package direct

import (
	"context"
	"fmt"
	"os"

	"go.londer.be/cardinal/internal/server/policy"
	"go.londer.be/cardinal/internal/store"
)

// WarnDangling reports what a policy names and the directory does not have.
//
// Shared, because both publishing a set and first-run setup do it. A rule
// naming a group that is not there never matches, and under a default-deny
// engine that looks exactly like the rule working.
func WarnDangling(ctx context.Context, s *store.Store, engine *policy.Engine) {
	dangling, err := engine.Dangling(ctx, s.PolicyReferenceExists)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  could not check what this policy names: %v\n", err)
		return
	}
	if len(dangling) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\nwarning: %s", policy.ExplainDangling(dangling))
}
