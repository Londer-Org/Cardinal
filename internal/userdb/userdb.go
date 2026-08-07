// Package userdb serves POSIX identity to systemd's nss-systemd.
//
// This is the replacement for nss_ldap, and the reason it is worth having is
// what it is *not*: nss_ldap is a shared library loaded into every process on
// the system that resolves a name — sshd, sudo, ls -l, anything. Writing one
// means writing C that runs everywhere, cannot block for long, must be
// thread-safe, and takes the whole process down with it if it faults.
//
// systemd's io.systemd.UserDatabase interface moves that out of process. An
// ordinary Go service answers over a Unix socket, nss-systemd does the loading,
// and an agent that crashes stops answering rather than taking sshd with it.
// ADR 0020 records the spike that established this works.
//
// The wire format is the whole of the framing: NUL-terminated JSON, one object
// per message. No varlink library, no cgo, and nothing here beyond the standard
// library.
package userdb

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
)

// Interface names, exactly as systemd spells them.
const (
	Interface = "io.systemd.UserDatabase"

	methodGetUserRecord  = Interface + ".GetUserRecord"
	methodGetGroupRecord = Interface + ".GetGroupRecord"
	methodGetMemberships = Interface + ".GetMemberships"
)

// The errors this interface defines. Returned by name; systemd matches on the
// string, so these are protocol and not diagnostics.
const (
	errNoRecordFound            = Interface + ".NoRecordFound"
	errBadService               = Interface + ".BadService"
	errServiceNotAvailable      = Interface + ".ServiceNotAvailable"
	errEnumerationNotSupported  = Interface + ".EnumerationNotSupported"
	errInterfaceMethodNotFound  = "org.varlink.service.MethodNotFound"
	errInterfaceInvalidArgument = "org.varlink.service.InvalidParameter"
)

// UserRecord is a systemd JSON User Record, in the subset that matters.
//
// Deliberately not the whole specification, which is large and mostly about
// things a directory does not own — disk quotas, storage backends, password
// policy. What is here is what `getent passwd` renders and what sshd needs.
type UserRecord struct {
	UserName      string `json:"userName"`
	UID           int    `json:"uid"`
	GID           int    `json:"gid"`
	HomeDirectory string `json:"homeDirectory"`
	Shell         string `json:"shell"`

	// Disposition tells systemd what kind of account this is. "regular" means a
	// human being, which affects whether tools like `loginctl` and the GNOME
	// greeter offer it.
	Disposition string `json:"disposition"`

	// Service names the provider this record came from.
	//
	// Set because the record format defines it and systemd's own providers set
	// it. Deliberately *not* relied on: setting it to a wrong value and asking
	// `getent` produced a correct answer anyway, so nss-systemd 255 does not
	// validate this field. The check that does bite is on the request side —
	// see Server.ServiceName.
	Service string `json:"service"`

	// Deliberately absent: realName, which maps to the GECOS field. It is
	// world-readable on every host — `getent passwd` needs no privilege — and a
	// person's real name is exactly the sort of thing that should not be
	// broadcast to every process on every machine they can log into.
}

// GroupRecord is a systemd JSON Group Record.
type GroupRecord struct {
	GroupName   string   `json:"groupName"`
	GID         int      `json:"gid"`
	Members     []string `json:"members,omitempty"`
	Disposition string   `json:"disposition"`
	Service     string   `json:"service"`
}

// Membership is one user-in-group pair.
type Membership struct {
	UserName  string `json:"userName"`
	GroupName string `json:"groupName"`
}

// Source is where records come from.
//
// An interface rather than a struct so the agent can swap the whole snapshot
// atomically on refresh, and so this package can be tested without an agent,
// a cache file, or a Cardinal.
type Source interface {
	UserByName(name string) (UserRecord, bool)
	UserByUID(uid int) (UserRecord, bool)
	GroupByName(name string) (GroupRecord, bool)
	GroupByGID(gid int) (GroupRecord, bool)
	MembershipsOf(userName, groupName string) []Membership
}

// Server answers io.systemd.UserDatabase over a Unix socket.
type Server struct {
	// ServiceName is the socket's basename, and systemd derives which service
	// to ask from exactly that, passing it back in every request.
	//
	// Load-bearing, and verified by the fact that anything works at all: a
	// provider whose name did not match what nss-systemd sends refuses every
	// request with BadService, so `getent` resolving anybody is proof the
	// handshake is real.
	ServiceName string

	// Source is read per request rather than held, so a refresh that replaces
	// the snapshot takes effect on the next question without restarting.
	Source func() Source

	Log *slog.Logger
}

// Serve accepts connections until the context is cancelled.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("userdb: accepting: %w", err)
		}

		wg.Go(func() {
			defer func() { _ = conn.Close() }()
			s.handle(ctx, conn)
		})
	}
}

type request struct {
	Method     string          `json:"method"`
	Parameters json.RawMessage `json:"parameters"`

	// More means the caller will accept several replies. systemd sets it for
	// enumeration and for GetMemberships, which is inherently multi-valued.
	More bool `json:"more"`
}

type reply struct {
	Parameters any    `json:"parameters,omitempty"`
	Continues  bool   `json:"continues,omitempty"`
	Error      string `json:"error,omitempty"`
}

// handle reads NUL-terminated JSON objects until the peer goes away.
func (s *Server) handle(ctx context.Context, conn net.Conn) {
	reader := bufio.NewReader(conn)

	for {
		if ctx.Err() != nil {
			return
		}

		raw, err := reader.ReadBytes(0)
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				s.log().Debug("userdb: read failed", "error", err)
			}
			return
		}
		raw = raw[:len(raw)-1] // drop the NUL

		var req request
		if err := json.Unmarshal(raw, &req); err != nil {
			_ = s.write(conn, reply{Error: errInterfaceInvalidArgument}, false)
			return
		}

		if err := s.dispatch(conn, req); err != nil {
			s.log().Debug("userdb: write failed", "error", err)
			return
		}
	}
}

type lookupParams struct {
	UID       *int    `json:"uid"`
	GID       *int    `json:"gid"`
	UserName  *string `json:"userName"`
	GroupName *string `json:"groupName"`
	Service   string  `json:"service"`
}

func (s *Server) dispatch(conn net.Conn, req request) error {
	var p lookupParams
	if len(req.Parameters) > 0 {
		if err := json.Unmarshal(req.Parameters, &p); err != nil {
			return s.write(conn, reply{Error: errInterfaceInvalidArgument}, false)
		}
	}

	// Checked before anything else, and checked at all because nss-systemd
	// passes back the name it derived from the socket path. A provider that
	// answered regardless would be answering questions meant for a different
	// service, and the caller would believe it.
	if p.Service != s.ServiceName {
		return s.write(conn, reply{Error: errBadService}, false)
	}

	source := s.Source()
	if source == nil {
		// Nothing cached yet and Cardinal unreachable. Distinguished from
		// "no such user" on purpose: this one means ask again later, and
		// systemd falls through to the next NSS source rather than concluding
		// the account does not exist.
		return s.write(conn, reply{Error: errServiceNotAvailable}, false)
	}

	switch req.Method {
	case methodGetUserRecord:
		return s.getUser(conn, source, p)
	case methodGetGroupRecord:
		return s.getGroup(conn, source, p)
	case methodGetMemberships:
		return s.getMemberships(conn, source, req.More, p)
	default:
		return s.write(conn, reply{Error: errInterfaceMethodNotFound}, false)
	}
}

type recordReply struct {
	Record any `json:"record"`
}

func (s *Server) getUser(conn net.Conn, source Source, p lookupParams) error {
	switch {
	case p.UserName != nil && p.UID != nil:
		// Both given means "this name must have this uid". Answering either
		// half would let a caller confirm a guess about the other.
		record, ok := source.UserByName(*p.UserName)
		if !ok || record.UID != *p.UID {
			return s.write(conn, reply{Error: errNoRecordFound}, false)
		}
		return s.write(conn, reply{Parameters: recordReply{Record: s.stampUser(record)}}, false)

	case p.UserName != nil:
		record, ok := source.UserByName(*p.UserName)
		if !ok {
			return s.write(conn, reply{Error: errNoRecordFound}, false)
		}
		return s.write(conn, reply{Parameters: recordReply{Record: s.stampUser(record)}}, false)

	case p.UID != nil:
		record, ok := source.UserByUID(*p.UID)
		if !ok {
			return s.write(conn, reply{Error: errNoRecordFound}, false)
		}
		return s.write(conn, reply{Parameters: recordReply{Record: s.stampUser(record)}}, false)

	default:
		// Neither given means "list everything", and the interface has an error
		// for declining exactly that. `getent passwd` with no argument will not
		// show Cardinal users, which is the correct trade: a host holds only its
		// own people (ADR 0025), so enumerating would advertise precisely the
		// set worth not advertising.
		return s.write(conn, reply{Error: errEnumerationNotSupported}, false)
	}
}

func (s *Server) getGroup(conn net.Conn, source Source, p lookupParams) error {
	switch {
	case p.GroupName != nil && p.GID != nil:
		record, ok := source.GroupByName(*p.GroupName)
		if !ok || record.GID != *p.GID {
			return s.write(conn, reply{Error: errNoRecordFound}, false)
		}
		return s.write(conn, reply{Parameters: recordReply{Record: s.stampGroup(record)}}, false)

	case p.GroupName != nil:
		record, ok := source.GroupByName(*p.GroupName)
		if !ok {
			return s.write(conn, reply{Error: errNoRecordFound}, false)
		}
		return s.write(conn, reply{Parameters: recordReply{Record: s.stampGroup(record)}}, false)

	case p.GID != nil:
		record, ok := source.GroupByGID(*p.GID)
		if !ok {
			return s.write(conn, reply{Error: errNoRecordFound}, false)
		}
		return s.write(conn, reply{Parameters: recordReply{Record: s.stampGroup(record)}}, false)

	default:
		return s.write(conn, reply{Error: errEnumerationNotSupported}, false)
	}
}

// getMemberships is the one method that answers more than once.
//
// `id alice` is the caller: it needs every group she is in, and the interface
// expresses that as a stream of pairs rather than a list inside one reply.
func (s *Server) getMemberships(conn net.Conn, source Source, more bool, p lookupParams) error {
	var user, group string
	if p.UserName != nil {
		user = *p.UserName
	}
	if p.GroupName != nil {
		group = *p.GroupName
	}

	if user == "" && group == "" {
		return s.write(conn, reply{Error: errEnumerationNotSupported}, false)
	}

	found := source.MembershipsOf(user, group)
	if len(found) == 0 {
		return s.write(conn, reply{Error: errNoRecordFound}, false)
	}

	// A caller that did not ask for several replies gets one. Sending a stream
	// to a client expecting a single answer is a protocol violation, and the
	// symptom is a hang rather than an error.
	if !more {
		return s.write(conn, reply{Parameters: found[0]}, false)
	}

	for i, m := range found {
		last := i == len(found)-1
		if err := s.write(conn, reply{Parameters: m, Continues: !last}, false); err != nil {
			return err
		}
	}
	return nil
}

// stampUser fills in the fields the caller must not set.
//
// Service comes from configuration rather than from the record, so a cache file
// somebody edited cannot make this provider claim to be a different identity
// source. That is defence for its own sake — nss-systemd 255 does not check the
// field, tested — but the cost is one assignment and the alternative is trusting
// a file on disk to describe the process reading it.
func (s *Server) stampUser(r UserRecord) UserRecord {
	r.Service = s.ServiceName
	if r.Disposition == "" {
		r.Disposition = "regular"
	}
	return r
}

func (s *Server) stampGroup(r GroupRecord) GroupRecord {
	r.Service = s.ServiceName
	if r.Disposition == "" {
		r.Disposition = "regular"
	}
	return r
}

func (s *Server) write(conn net.Conn, msg reply, _ bool) error {
	encoded, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("userdb: encoding reply: %w", err)
	}
	if _, err := conn.Write(append(encoded, 0)); err != nil {
		return fmt.Errorf("userdb: writing reply: %w", err)
	}
	return nil
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// SocketPath is where nss-systemd looks.
//
// The basename *is* the service name — that is the whole discovery mechanism —
// so the two must be derived from one value rather than written twice.
func SocketPath(runDir, serviceName string) string {
	return strings.TrimRight(runDir, "/") + "/" + serviceName
}

// DefaultRunDir is the directory nss-systemd scans.
const DefaultRunDir = "/run/systemd/userdb"

// ServiceName is the name Cardinal's provider registers under.
const ServiceName = "io.systemd.Cardinal"
