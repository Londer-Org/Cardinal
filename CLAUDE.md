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

## The website is documentation, and it lives in another repository

Presentation and user-facing documentation are in
[cardinal-website](https://github.com/Londer-Org/cardinal-website), not here.
That split is deliberate — a marketing page has no reason to be versioned
alongside a server — and it has one cost: a change here can make a page there
false, and nothing in this repository will fail when it does.

So the rule is that **a change is not finished until the website says the same
thing.** Ask it every time, and act on the answer in the same piece of work
rather than filing it:

- **New or changed command, flag, or console view?** The site's guides show
  commands. `cardinal decisions` and `cardinal history -at` are in them.
- **Changed behaviour a page describes?** Erasure, sessions, policy
  evaluation, host enrolment and key rotation are all described there in
  prose that can quietly stop being true.
- **New configuration key, or one removed?** `docs/configuration.md` on the
  site lists the sections and the three encryption keys that must differ.
- **A capability gained or lost?** The landing page, the feature tabs, the FAQ
  in the structured data and `public/llms.txt` all enumerate what Cardinal
  does. An answer engine quoting a stale list is worse than one quoting
  nothing.
- **A release?** `CHANGELOG.md` here is the source, and the version shown in
  the site's header is a constant in `lib/site.ts` that has to be bumped. The
  screenshots on the site carry the version in the console's sidebar, so a
  release that changes the console visibly means recapturing them with
  `tools/uishot`.

The screenshots on that site were captured from a real running Cardinal
against the end-to-end stack, and they must stay that way. Do not mock one up,
and do not keep one that no longer matches the console — a fabricated
screenshot of a security product is a claim nobody can check.

If a website change is genuinely out of scope for the work in hand, say so
explicitly in the handover rather than leaving it to be discovered. Silence
reads as "nothing to update", and this project's recurring bug is a claim that
stopped being true while everything still compiled.
