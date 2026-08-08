package userdb_test

import (
	"context"
	"encoding/json"
	"maps"
	"net"
	"path/filepath"
	"testing"
	"time"

	"go.londer.be/cardinal/internal/userdb"
)

// The wire protocol, exercised over a real Unix socket.
//
// These prove the implementation is self-consistent and nothing more. Whether
// nss-systemd agrees is a different question that no Go test can answer, and it
// is answered by `make verify-userdb`, which runs `getent` against this server
// inside a container.

type fixture struct{}

func (fixture) UserByName(name string) (userdb.UserRecord, bool) {
	if name != "alice" {
		return userdb.UserRecord{}, false
	}
	return alice, true
}

func (fixture) UserByUID(uid int) (userdb.UserRecord, bool) {
	if uid != 100000 {
		return userdb.UserRecord{}, false
	}
	return alice, true
}

func (fixture) GroupByName(name string) (userdb.GroupRecord, bool) {
	if name != "sre" {
		return userdb.GroupRecord{}, false
	}
	return sre, true
}

func (fixture) GroupByGID(gid int) (userdb.GroupRecord, bool) {
	if gid != 100001 {
		return userdb.GroupRecord{}, false
	}
	return sre, true
}

func (fixture) MembershipsOf(userName, groupName string) []userdb.Membership {
	all := []userdb.Membership{
		{UserName: "alice", GroupName: "sre"},
		{UserName: "alice", GroupName: "oncall"},
		{UserName: "bob", GroupName: "sre"},
	}
	out := []userdb.Membership{}
	for _, m := range all {
		if userName != "" && m.UserName != userName {
			continue
		}
		if groupName != "" && m.GroupName != groupName {
			continue
		}
		out = append(out, m)
	}
	return out
}

var (
	alice = userdb.UserRecord{
		UserName: "alice", UID: 100000, GID: 100000,
		HomeDirectory: "/home/alice", Shell: "/bin/bash",
	}
	sre = userdb.GroupRecord{
		GroupName: "sre", GID: 100001, Members: []string{"alice", "bob"},
	}
)

// client is a minimal varlink caller: NUL-terminated JSON, nothing else.
type client struct{ conn net.Conn }

func dial(t *testing.T, source func() userdb.Source) *client {
	t.Helper()

	path := filepath.Join(t.TempDir(), userdb.ServiceName)
	listener, err := net.Listen("unix", path) //nolint:noctx // a test listener, torn down by Cleanup
	if err != nil {
		t.Fatal(err)
	}

	server := &userdb.Server{ServiceName: userdb.ServiceName, Source: source}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()

	conn, err := net.Dial("unix", path) //nolint:noctx // a test dial with an explicit read deadline
	if err != nil {
		cancel()
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_ = conn.Close()
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop")
		}
	})

	return &client{conn: conn}
}

type response struct {
	Parameters json.RawMessage `json:"parameters"`
	Continues  bool            `json:"continues"`
	Error      string          `json:"error"`
}

func (c *client) call(t *testing.T, method string, params map[string]any, more bool) []response {
	t.Helper()

	request := map[string]any{"method": method, "parameters": params}
	if more {
		request["more"] = true
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.conn.Write(append(encoded, 0)); err != nil {
		t.Fatal(err)
	}

	var out []response
	buf := make([]byte, 1)
	message := []byte{}
	for {
		if err := c.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		n, err := c.conn.Read(buf)
		if err != nil {
			t.Fatalf("reading reply: %v", err)
		}
		if n == 0 {
			continue
		}
		if buf[0] != 0 {
			message = append(message, buf[0])
			continue
		}

		var r response
		if err := json.Unmarshal(message, &r); err != nil {
			t.Fatalf("reply is not JSON: %s", message)
		}
		out = append(out, r)
		message = message[:0]

		if !r.Continues {
			return out
		}
	}
}

func fixtureSource() userdb.Source { return fixture{} }

func params(extra map[string]any) map[string]any {
	p := map[string]any{"service": userdb.ServiceName}
	maps.Copy(p, extra)
	return p
}

// TestLookupByNameAndByUID.
//
// Both directions, because `getent passwd alice` and `ls -l` use different ones
// and a provider that answered only the first would look correct until somebody
// listed a directory.
func TestLookupByNameAndByUID(t *testing.T) {
	c := dial(t, fixtureSource)

	for _, tc := range []struct {
		name  string
		query map[string]any
	}{
		{"by name", params(map[string]any{"userName": "alice"})},
		{"by uid", params(map[string]any{"uid": 100000})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replies := c.call(t, "io.systemd.UserDatabase.GetUserRecord", tc.query, false)
			if len(replies) != 1 {
				t.Fatalf("got %d replies, want 1", len(replies))
			}
			if replies[0].Error != "" {
				t.Fatalf("error %q", replies[0].Error)
			}

			var body struct {
				Record userdb.UserRecord `json:"record"`
			}
			if err := json.Unmarshal(replies[0].Parameters, &body); err != nil {
				t.Fatal(err)
			}
			if body.Record.UserName != "alice" || body.Record.UID != 100000 {
				t.Fatalf("wrong record: %+v", body.Record)
			}
			if body.Record.HomeDirectory != "/home/alice" || body.Record.Shell != "/bin/bash" {
				t.Fatalf("incomplete record: %+v", body.Record)
			}

			// Asserted because the record format defines the field, not because
			// nss-systemd enforces it — setting it wrong and asking `getent`
			// produced a correct answer anyway on systemd 255. See ADR 0020.
			if body.Record.Service != userdb.ServiceName {
				t.Fatalf("service %q, want %q", body.Record.Service, userdb.ServiceName)
			}
			if body.Record.Disposition != "regular" {
				t.Fatalf("disposition %q, want regular", body.Record.Disposition)
			}
		})
	}
}

// TestUnknownNameIsNoRecordFound.
//
// The error has to be this one specifically. Anything else and nss-systemd
// treats the lookup as broken rather than as a miss, which changes whether it
// falls through to the next source in nsswitch.conf.
func TestUnknownNameIsNoRecordFound(t *testing.T) {
	c := dial(t, fixtureSource)

	replies := c.call(t, "io.systemd.UserDatabase.GetUserRecord",
		params(map[string]any{"userName": "nobody"}), false)

	if replies[0].Error != "io.systemd.UserDatabase.NoRecordFound" {
		t.Fatalf("got %q, want NoRecordFound", replies[0].Error)
	}
}

// TestConflictingNameAndUIDIsRefused.
//
// Given both, the request means "this name must have this number". Answering
// either half would let a caller confirm a guess about the other.
func TestConflictingNameAndUIDIsRefused(t *testing.T) {
	c := dial(t, fixtureSource)

	replies := c.call(t, "io.systemd.UserDatabase.GetUserRecord",
		params(map[string]any{"userName": "alice", "uid": 999999}), false)

	if replies[0].Error != "io.systemd.UserDatabase.NoRecordFound" {
		t.Fatalf("got %q, want NoRecordFound", replies[0].Error)
	}
}

// TestWrongServiceIsRefused.
//
// nss-systemd derives the service from the socket's filename and passes it
// back. A provider that answered regardless would be answering questions
// addressed to somebody else, and the caller would believe it.
func TestWrongServiceIsRefused(t *testing.T) {
	c := dial(t, fixtureSource)

	replies := c.call(t, "io.systemd.UserDatabase.GetUserRecord",
		map[string]any{"service": "io.systemd.SomebodyElse", "userName": "alice"}, false)

	if replies[0].Error != "io.systemd.UserDatabase.BadService" {
		t.Fatalf("got %q, want BadService", replies[0].Error)
	}
}

// TestEnumerationIsRefused.
//
// A host holds only its own people (ADR 0025), so listing them would advertise
// exactly the set worth not advertising. The interface has an error for
// declining, which is what makes this a supported answer rather than a gap.
func TestEnumerationIsRefused(t *testing.T) {
	c := dial(t, fixtureSource)

	for _, method := range []string{
		"io.systemd.UserDatabase.GetUserRecord",
		"io.systemd.UserDatabase.GetGroupRecord",
		"io.systemd.UserDatabase.GetMemberships",
	} {
		t.Run(method, func(t *testing.T) {
			replies := c.call(t, method, params(nil), true)
			if replies[0].Error != "io.systemd.UserDatabase.EnumerationNotSupported" {
				t.Fatalf("got %q, want EnumerationNotSupported", replies[0].Error)
			}
		})
	}
}

// TestMembershipsStreamUntilTheLast.
//
// `id alice` needs every group she is in, and the interface expresses that as
// several replies rather than a list. The last one must not set `continues`, or
// the caller waits forever for a reply that is never sent.
func TestMembershipsStreamUntilTheLast(t *testing.T) {
	c := dial(t, fixtureSource)

	replies := c.call(t, "io.systemd.UserDatabase.GetMemberships",
		params(map[string]any{"userName": "alice"}), true)

	if len(replies) != 2 {
		t.Fatalf("got %d replies, want 2 (sre and oncall)", len(replies))
	}
	if !replies[0].Continues {
		t.Fatal("the first of several replies must set continues")
	}
	if replies[1].Continues {
		t.Fatal("the last reply must not set continues — the caller would hang")
	}

	for _, r := range replies {
		var m userdb.Membership
		if err := json.Unmarshal(r.Parameters, &m); err != nil {
			t.Fatal(err)
		}
		if m.UserName != "alice" {
			t.Fatalf("membership for the wrong user: %+v", m)
		}
	}
}

// TestSingleReplyWhenTheCallerDidNotAskForMore.
//
// Sending a stream to a client expecting one answer is a protocol violation
// whose symptom is a hang, not an error.
func TestSingleReplyWhenTheCallerDidNotAskForMore(t *testing.T) {
	c := dial(t, fixtureSource)

	replies := c.call(t, "io.systemd.UserDatabase.GetMemberships",
		params(map[string]any{"userName": "alice"}), false)

	if len(replies) != 1 {
		t.Fatalf("got %d replies, want 1", len(replies))
	}
	if replies[0].Continues {
		t.Fatal("a single reply must not set continues")
	}
}

// TestNoSourceIsServiceNotAvailable.
//
// A host that has never refreshed and cannot reach Cardinal. Distinguished from
// "no such user" on purpose: this one means ask again later, so systemd falls
// through to the next NSS source instead of concluding the account is gone.
func TestNoSourceIsServiceNotAvailable(t *testing.T) {
	c := dial(t, func() userdb.Source { return nil })

	replies := c.call(t, "io.systemd.UserDatabase.GetUserRecord",
		params(map[string]any{"userName": "alice"}), false)

	if replies[0].Error != "io.systemd.UserDatabase.ServiceNotAvailable" {
		t.Fatalf("got %q, want ServiceNotAvailable", replies[0].Error)
	}
}

// TestGroupLookup.
func TestGroupLookup(t *testing.T) {
	c := dial(t, fixtureSource)

	replies := c.call(t, "io.systemd.UserDatabase.GetGroupRecord",
		params(map[string]any{"groupName": "sre"}), false)

	var body struct {
		Record userdb.GroupRecord `json:"record"`
	}
	if err := json.Unmarshal(replies[0].Parameters, &body); err != nil {
		t.Fatal(err)
	}
	if body.Record.GID != 100001 || len(body.Record.Members) != 2 {
		t.Fatalf("wrong record: %+v", body.Record)
	}
	if body.Record.Service != userdb.ServiceName {
		t.Fatalf("service %q", body.Record.Service)
	}
}

// TestSeveralCallsOnOneConnection.
//
// nss-systemd reuses a connection, so a server that handled one request and
// closed would work in a test that opened a socket per call and fail in
// practice.
func TestSeveralCallsOnOneConnection(t *testing.T) {
	c := dial(t, fixtureSource)

	for range 3 {
		replies := c.call(t, "io.systemd.UserDatabase.GetUserRecord",
			params(map[string]any{"userName": "alice"}), false)
		if replies[0].Error != "" {
			t.Fatalf("error on reuse: %q", replies[0].Error)
		}
	}
}

// TestUnknownMethod.
func TestUnknownMethod(t *testing.T) {
	c := dial(t, fixtureSource)

	replies := c.call(t, "io.systemd.UserDatabase.DoSomethingElse", params(nil), false)
	if replies[0].Error != "org.varlink.service.MethodNotFound" {
		t.Fatalf("got %q, want MethodNotFound", replies[0].Error)
	}
}
