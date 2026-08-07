package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/arthur-lonfils/cardinal/internal/hostclient"
	"github.com/arthur-lonfils/cardinal/internal/userdb"
)

// DefaultInterval is how often the agent asks Cardinal for its assignment.
//
// Five minutes. Short enough that revoking somebody's access reaches the fleet
// while the person revoking it is still at their desk; long enough that a
// thousand hosts are two hundred requests a minute rather than a load problem.
//
// It is not a security boundary. SSH access is decided at certificate issuance
// and those certificates last minutes, so a stale assignment delays a name
// resolving, not a login being authorised.
const DefaultInterval = 5 * time.Minute

// Agent keeps this host's assignment current and readable.
type Agent struct {
	Identity *hostclient.Identity
	Client   *http.Client

	CachePath string
	Interval  time.Duration

	Log *slog.Logger

	// snapshot is swapped wholesale on each successful refresh, so a lookup
	// either sees the old assignment or the new one and never a half-applied
	// mixture.
	snapshot atomic.Pointer[Snapshot]

	// current is kept alongside for reporting: age, counts, the unnumbered
	// list. Swapped in the same operation.
	current atomic.Pointer[Assignment]
}

// Source is what the varlink provider reads. Nil until something is loaded,
// which the provider reports as ServiceNotAvailable rather than "no such user".
func (a *Agent) Source() userdb.Source {
	s := a.snapshot.Load()
	if s == nil {
		// A typed nil in an interface is not a nil interface, so this must
		// return an untyped nil or every caller's nil check silently fails.
		return nil
	}
	return s
}

// Assignment returns what is currently being served, if anything.
func (a *Agent) Assignment() *Assignment { return a.current.Load() }

// LoadCache primes the agent from disk.
//
// Called before the first fetch and before the socket is served, which is the
// whole offline story: a machine that reboots while Cardinal is down comes up
// answering from what it last knew. A missing cache is not an error — it is a
// host that has never successfully refreshed — so the caller decides whether
// that is fatal.
func (a *Agent) LoadCache() (*Assignment, error) {
	cached, err := Load(a.cachePath())
	if err != nil {
		return nil, err
	}
	a.install(cached)
	return cached, nil
}

// Refresh fetches the assignment and replaces the cache.
func (a *Agent) Refresh(ctx context.Context) (*Assignment, error) {
	resp, err := a.Identity.Do(ctx, a.client(), http.MethodGet, "/api/hosts/assignment", nil)
	if err != nil {
		return nil, fmt.Errorf("agent: fetching assignment: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("agent: Cardinal refused the assignment: %s",
			describe(resp))
	}

	var fetched Assignment
	if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(&fetched); err != nil {
		return nil, fmt.Errorf("agent: reading assignment: %w", err)
	}
	fetched.FetchedAt = time.Now()

	// An empty assignment is accepted as an answer. It looks alarming and is
	// legitimate — a host removed from its group should stop resolving those
	// people — and the endpoint fails closed with 503 rather than returning an
	// empty 200 when it cannot decide, so a 200 here really is a decision.
	if len(fetched.Users) == 0 {
		a.log().Warn("assignment is empty: nobody may log into this host")
	}

	// Cache first, install second. A crash between the two costs one refresh
	// interval; the other order costs the cache being older than what is being
	// served, which is the state that makes an outage confusing to reason about.
	if err := Save(a.cachePath(), &fetched); err != nil {
		return nil, err
	}
	a.install(&fetched)

	return &fetched, nil
}

// Run refreshes on a schedule until the context is cancelled.
//
// A failed refresh is logged and nothing else: whatever is already installed
// keeps being served. That is the entire point — an agent that cleared its
// records when Cardinal became unreachable would turn a directory outage into a
// fleet outage, which is the failure mode this design exists to avoid.
func (a *Agent) Run(ctx context.Context) error {
	interval := a.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if _, err := a.Refresh(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			served := "nothing cached yet"
			if current := a.Assignment(); current != nil {
				served = fmt.Sprintf("still serving records from %s ago",
					current.Age().Round(time.Second))
			}
			a.log().Warn("refresh failed", "error", err, "state", served)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (a *Agent) install(assignment *Assignment) {
	a.snapshot.Store(NewSnapshot(assignment))
	a.current.Store(assignment)
}

func (a *Agent) cachePath() string {
	if a.CachePath != "" {
		return a.CachePath
	}
	return DefaultCachePath
}

func (a *Agent) client() *http.Client {
	if a.Client != nil {
		return a.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (a *Agent) log() *slog.Logger {
	if a.Log != nil {
		return a.Log
	}
	return slog.Default()
}

// CacheMissing reports whether the error from LoadCache is simply a host that
// has never refreshed, rather than a cache that is there and broken.
func CacheMissing(err error) bool { return errors.Is(err, os.ErrNotExist) }

func describe(resp *http.Response) string {
	var body struct {
		Error string `json:"error"`
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err == nil && json.Unmarshal(raw, &body) == nil && body.Error != "" {
		return resp.Status + " — " + body.Error
	}
	return resp.Status
}
