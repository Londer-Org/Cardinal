# Cardinal — conventions for AI assistants

Project-level rules. Where these disagree with the global `~/.claude/CLAUDE.md`,
these win, because they were decided against this codebase rather than in
general.

## Commit messages

Follow the convention used in the `cm` project.

**Subject.** One line, capitalised, declarative, under about 70 characters. No
`type(scope):` prefix, no trailing full stop. Say what the commit does, not what
was wrong:

```
Add service users
Fix users column sorting losing context
Replace Bootstrap tabs with Tailwind and React
Improve Rails version config
```

**Body.** Only when the subject cannot carry it — roughly half of commits have
none at all. Prose paragraphs, wrapped at 72–76 columns, explaining *why*. A
bullet list is fine for enumerating what a large change contains. A ticket or
ADR reference goes on its own line at the end.

**No attribution footer.** Not `Assisted by:`, not `Co-Authored-By:`, not a
session URL. The global instruction mandating `Assisted by:` does not apply
here. The repo's hook still rejects `Co-Authored-By:` — if it fires, fix the
message, never the hook.

## Linting

`.golangci.yml` is strict deliberately, and the code is expected to satisfy it
rather than the config being relaxed to match the code. If a linter flags
something intentional, the fix is a `//nolint:<linter> // <reason>` carrying the
reasoning — not a new exclusion. `nolintlint` is enabled, so a directive that
stops being needed becomes an error rather than lingering.

## Comments

Comments explain *why*, and are expected to be true. Several bugs in this
project's history were a comment asserting something nobody had measured. If a
comment makes a factual claim about the behaviour of a dependency, the operating
system, or a database, check it before writing it — and if you checked, the
comment may as well say what was observed.
