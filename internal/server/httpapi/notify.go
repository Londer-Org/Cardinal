package httpapi

import (
	"context"

	"github.com/google/uuid"
	"go.londer.be/cardinal/internal/directory"
	"go.londer.be/cardinal/internal/server/mail"
)

// notify tells somebody what just happened to their account.
//
// Best effort, and deliberately so. Every caller here has already done the thing
// being reported — the passkey is registered, the code is spent — so a mail
// problem must not turn a completed action into an error. What it can do is be
// visible in the log, which is what the notifier does.
//
// Nothing here authorises anything (ADR 0009). The value is detection: somebody
// who reads "a passkey was added" and did not add one has found out.
func (s *Server) notify(ctx context.Context, subjectID uuid.UUID, kind mail.Kind, url string) {
	if s.notifier == nil {
		return
	}

	// The address is read here rather than passed in, because every caller
	// would otherwise have to remember to fetch it and one of them eventually
	// would not.
	entity, err := s.store.GetEntity(ctx, subjectID)
	if err != nil {
		return
	}
	if entity.Type != directory.TypeUser {
		// Hosts and service accounts have no mailbox and no person behind them.
		return
	}
	address, _ := entity.Attrs["email"].(string) //nolint:errcheck // a missing or non-string attribute is the empty string

	// nil transaction: these are called after the change has committed, which
	// is a window store.EnqueueMail documents.
	s.notifier.Notify(ctx, nil, &subjectID, address, entity.Name, kind, url)
}
