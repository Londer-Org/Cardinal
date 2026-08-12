package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Where a signed-in terminal keeps its session.
//
// A credential at rest, and there is no pretending otherwise. What makes it
// acceptable is that it is the same credential a browser keeps in its cookie
// jar: it expires, it is revocable from the console, and Cedar already refuses
// a stale session the privileged actions — so a stolen cache cannot approve a
// recovery or issue an SSH certificate without a new ceremony.
//
// Keyed by server URL so two deployments do not collide, and 0600 because
// anything else would put it within reach of every process on a shared machine.

const cacheMode = 0o600

type cacheFile struct {
	Sessions map[string]*Session `json:"sessions"`
}

// CachePath is where the file lives, honouring XDG_CONFIG_HOME.
func CachePath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("finding the home directory: %w", err)
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "cardinal", "sessions.json"), nil
}

// Cached returns the session for a server, or ErrNotSignedIn.
func Cached(base string) (*Session, error) {
	path, err := CachePath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path) //nolint:gosec // a path this process computed
	if err != nil {
		return nil, ErrNotSignedIn
	}

	var file cacheFile
	if err := json.Unmarshal(raw, &file); err != nil {
		// A cache that will not parse is one to replace, not one to fail on:
		// the cost of being wrong is a browser approval.
		return nil, ErrNotSignedIn
	}
	session := file.Sessions[base]
	if session == nil || session.Token == "" {
		return nil, ErrNotSignedIn
	}
	if !session.ExpiresAt.IsZero() && time.Now().After(session.ExpiresAt) {
		return nil, ErrNotSignedIn
	}
	return session, nil
}

// Remember writes a session for a server, leaving any others in place.
func Remember(base string, session *Session) error {
	path, err := CachePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}

	file := cacheFile{Sessions: map[string]*Session{}}
	if raw, readErr := os.ReadFile(path); readErr == nil { //nolint:gosec // as above
		_ = json.Unmarshal(raw, &file) //nolint:errcheck // an unreadable cache is replaced
	}
	if file.Sessions == nil {
		file.Sessions = map[string]*Session{}
	}
	file.Sessions[base] = session

	encoded, marshalErr := json.MarshalIndent(file, "", "  ")
	if marshalErr != nil {
		return marshalErr
	}
	// Written to a temporary file and renamed, so a crash midway leaves the
	// previous cache rather than a truncated one.
	tmp := path + ".tmp"
	if writeErr := os.WriteFile(tmp, encoded, cacheMode); writeErr != nil {
		return fmt.Errorf("writing %s: %w", tmp, writeErr)
	}
	if renameErr := os.Rename(tmp, path); renameErr != nil {
		return fmt.Errorf("replacing %s: %w", path, renameErr)
	}
	return nil
}

// Forget drops the session for a server. Used by sign-out and by a caller that
// has just been told its credential is no longer accepted.
func Forget(base string) error {
	path, err := CachePath()
	if err != nil {
		return err
	}
	// No cache, or one that will not parse, means there is nothing to forget —
	// which is the state the caller asked for, so it is not an error.
	raw, readErr := os.ReadFile(path) //nolint:gosec // as above
	if readErr != nil {
		return nil //nolint:nilerr // nothing cached is the desired end state
	}
	var file cacheFile
	if json.Unmarshal(raw, &file) != nil {
		return nil //nolint:nilerr // as above: an unparseable cache holds nothing to forget
	}
	delete(file.Sessions, base)

	encoded, marshalErr := json.MarshalIndent(file, "", "  ")
	if marshalErr != nil {
		return marshalErr
	}
	return os.WriteFile(path, encoded, cacheMode)
}
