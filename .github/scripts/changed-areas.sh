#!/bin/sh
# Which parts of CI a change actually needs.
#
# Reads changed paths on stdin, one per line, and writes `key=true|false` for
# each area. The workflow gates its jobs on those.
#
# The bias is deliberate and one-directional: when in doubt, run it. A filter
# that wrongly runs a job costs four minutes. A filter that wrongly skips one
# reports success for something nobody checked, which is the failure this
# repository keeps finding in other forms.
#
# Two couplings here are not obvious from a file's extension, and both would be
# broken by the "skip CI for docs" filter everybody writes first:
#
#   docs/schema.md is generated from the live schema and compared against it by
#   TestSchemaDocumentMatchesTheSchema, so editing it is a Go test.
#
#   internal/lint walks .sql, .ts and .tsx as well as .go, so a comment in the
#   frontend can fail a Go test.
set -eu

go=false
frontend=false
image=false
e2e=false
everything=false

while IFS= read -r path; do
    [ -n "$path" ] || continue

    case "$path" in
        # A change to CI itself has to be exercised by CI itself.
        .github/workflows/*|.github/scripts/*) everything=true ;;
    esac

    case "$path" in
        *.go|go.mod|go.sum|.golangci.yml|migrations/*|docs/schema.md|*.sql|*.ts|*.tsx)
            go=true ;;
    esac

    case "$path" in
        web/*) frontend=true ;;
    esac

    # The image compiles the UI and embeds it, so it moves with both halves.
    case "$path" in
        Dockerfile|web/*|*.go|go.mod|go.sum|migrations/*) image=true ;;
    esac

    # Everything the image needs, plus what drives the stack it runs in.
    case "$path" in
        Dockerfile|web/*|*.go|go.mod|go.sum|migrations/*|examples/*|Makefile|test/e2e/*)
            e2e=true ;;
    esac
done

if [ "$everything" = true ]; then
    go=true
    frontend=true
    image=true
    e2e=true
fi

printf 'go=%s\nfrontend=%s\nimage=%s\ne2e=%s\n' "$go" "$frontend" "$image" "$e2e"
