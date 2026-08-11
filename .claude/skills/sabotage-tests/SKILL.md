---
name: sabotage-tests
description: Prove a test can fail before trusting it. Use after writing or changing any test, assertion, CI check, migration guard or verification script — and whenever a test passes on the first run.
---

# Sabotage the check

A test that has never failed has not been tested. Break the thing it guards,
watch it fail, put it back. If it stays green, it was measuring something else.

This repository has a table of bugs that shipped with passing tests. Four of six
in one audit had one. The habit below is what catches that class.

## The loop

1. Run the check. It passes.
2. Break the specific property it claims to hold.
3. Run again. **It must fail, and the message must name the real problem.**
4. Restore. Run again. Green.

Keep a copy before editing (`cp x.go /tmp/x.bak`) — restoring from memory is how
a sabotage gets left in.

## A sabotage is only valid if it breaks the property

Break the behaviour, not the build. Both of these "fail", and only one means
anything:

```go
// Useless: removes $1 entirely, so the query errors and the test fails for
// a reason unrelated to the property.
WHERE delivered_at IS NULL AND jti = ANY($2)

// Valid: the predicate is still bound and still parses, and now permits what
// it was there to refuse.
WHERE (stream_id = $1 OR true) AND delivered_at IS NULL AND jti = ANY($2)
```

If the failure message is a compile error, a syntax error or a 500, the
sabotage is wrong. Fix the sabotage before concluding anything about the test.

## Sabotage both directions

A guard usually has two failure modes and tests often cover one:

- **Denies what it should permit** — visible, someone reports it.
- **Permits what it should deny** — silent, nobody reports it.

The second is the one worth the effort. For a disclosure control, check that it
fails *closed*: delete the row, drop the config, remove the flag, and confirm
the code shows less rather than everything.

## When a passing test proves nothing

Real cases from this repository:

- **The assertion only checked non-empty.** A timestamp built from two
  concatenated rows passed, because the test asked whether the string had
  length.
- **The ordinary path never reaches the default.** Every application gets a
  projection row, so the "missing row" branch — and the fail-closed decision it
  encodes — was unreachable from any test. Sabotaging it changed nothing.
- **The fixture predated the change.** The suite passed locally and failed in
  CI: a migration had backfilled a setting on existing rows while CI built the
  stack from nothing and got the new default. Run against state the change has
  never seen — `make e2e` rebuilds the database for this reason.
- **The test called the helper directly.** `RevokeTokensForSession` was tested,
  worked, and was called from nowhere. The test proved the helper, not the
  behaviour.

## After the sabotage

Say what you did and what you saw, in the commit or the PR — the exact
sabotage, the exact failure message. "Verified" without that is a claim in the
same category as the comment that turned out to be wrong.
