package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.londer.be/cardinal/internal/store"
	"go.londer.be/cardinal/migrations"
)

// What first-run setup records as having granted the first administrator.
//
// This is the last path that writes a membership with nobody authenticated:
// every other grant signs in and goes through the API. It is also the row an
// auditor reaches for first — how the first administrator became one — so an
// invented answer here is the most expensive one in the database.
//
// The end-to-end suite cannot cover it. That stack seeds its administrators
// with SQL because it needs several, and init deliberately refuses to run
// against a directory that already has one. So this brings up its own database.
func TestInitDoesNotRecordTheAdministratorAsTheirOwnGranter(t *testing.T) {
	if testing.Short() {
		t.Skip("brings up PostgreSQL")
	}

	ctx := t.Context()
	dsn := freshDatabase(ctx, t)
	t.Setenv("CARDINAL_DSN", dsn)

	// -no-policy because what is under test is the grant, and publishing the
	// built-in policy is a second thing that can fail for its own reasons.
	if err := runInit(ctx, []string{"-no-policy", "first-admin"}); err != nil {
		t.Fatalf("init: %v", err)
	}

	s, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("opening the database: %v", err)
	}
	defer s.Close()

	var member, granter string
	err = s.Pool().QueryRow(ctx, `
		SELECT e.name, g.name
		  FROM group_members m
		  JOIN entities grp ON grp.id = m.group_id
		  JOIN entities e   ON e.id   = m.member_id
		  JOIN entities g   ON g.id   = m.granted_by
		 WHERE grp.name = 'directory-admins'
		   AND m.valid_period @> now()`).Scan(&member, &granter)
	if err != nil {
		t.Fatalf("reading the administrator's membership: %v", err)
	}

	if granter == member {
		t.Fatalf("the first administrator (%s) is recorded as their own granter, "+
			"which nothing downstream can tell from a real self-grant", member)
	}
	if granter != "direct-database" {
		t.Errorf("granted_by is %q; first-run setup reaches the database with "+
			"nobody authenticated, so the only honest answer is direct-database",
			granter)
	}
}

// freshDatabase brings up PostgreSQL with the real migrations applied.
//
// Its own container rather than a shared one: init is a once-per-deployment
// command that refuses a database it has already run against, so it cannot
// share state with anything.
func freshDatabase(ctx context.Context, t *testing.T) string {
	t.Helper()

	image := os.Getenv("CARDINAL_TEST_POSTGRES_IMAGE")
	if image == "" {
		image = "postgres:19beta2"
	}

	container, err := tcpostgres.Run(ctx, image,
		tcpostgres.WithDatabase("cardinal_init_test"),
		tcpostgres.WithUsername("cardinal"),
		tcpostgres.WithPassword("cardinal"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		t.Fatalf("starting postgres: %v", err)
	}
	t.Cleanup(func() {
		if stopErr := testcontainers.TerminateContainer(container); stopErr != nil {
			t.Logf("terminating container: %v", stopErr)
		}
	})

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	if migrateErr := applyMigrations(ctx, dsn); migrateErr != nil {
		t.Fatalf("applying migrations: %v", migrateErr)
	}
	return dsn
}

// applyMigrations runs the real migration files through the same helper the
// migrator uses, so the schema under test cannot drift from the shipped one.
func applyMigrations(ctx context.Context, dsn string) error {
	s, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer s.Close()

	paths, err := migrations.Up()
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("no migrations embedded")
	}
	for _, path := range paths {
		sql, err := migrations.FS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		if _, err := s.Pool().Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("applying %s: %w", filepath.Base(path), err)
		}
	}
	return nil
}
