#!/usr/bin/env bash
# Prove that rolling back is redeploying the old image and nothing else.
#
# Cardinal's upgrade story rests on one promise: migrations are expand-only, so
# a previous build keeps working against a schema a newer one migrated. The
# expand-only rule is enforced per migration by `go test ./migrations/`, and
# `SchemaAhead` is unit-tested against synthetic rows — but until now nothing
# ever ran a real previous release against a real newer schema. The pairing was
# checked by reading, which is how this project's other bugs got in.
#
# So: migrate a database with the build in this checkout, then start a
# published release against it and ask it to serve.
#
# It asserts three things, and the third is the one with teeth:
#   1. The old build starts rather than refusing.
#   2. It answers /healthz.
#   3. Its log says the database is ahead of it — proving it noticed the drift
#      and chose to serve, rather than not having looked.
#
# Versions to test are arguments; the default is every release whose schema is
# genuinely older. 0.3.0 and 0.3.1 share a schema — 0.3.1 was documentation
# only — so testing against 0.3.0 would pass while exercising nothing.
set -euo pipefail

VERSIONS=("$@")
if [ ${#VERSIONS[@]} -eq 0 ]; then
  VERSIONS=(0.1.0 0.2.0)
fi

NET="cardinal-rollback-check"
PG="cardinal-rollback-pg"
APP="cardinal-rollback-app"
PGPASS="rollback-check-not-a-secret"
DSN="postgres://cardinal:${PGPASS}@${PG}:5432/cardinal?sslmode=disable"
# Under the repository rather than /tmp: Docker Desktop only shares selected
# host paths with the VM, and /tmp is not one of them — a bind mount from there
# fails with "path is not shared from the host".
WORK="$(mktemp -d "$PWD/.rollbackcheck.XXXXXX")"

cleanup() {
  docker rm -f "$APP" "$PG" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# A minimal configuration. The three authorities stay off, so the check needs
# none of their encryption keys — it is asking about the schema, not about
# issuing anything.
cat > "$WORK/cardinal.toml" <<EOF
[server]
listen = "0.0.0.0:8080"
public_url = "https://id.cardinal.test"
cookie_domain = "cardinal.test"

[database]
dsn = "$DSN"

[webauthn]
rp_id = "cardinal.test"
rp_display_name = "Rollback check"
origins = ["https://id.cardinal.test"]
EOF

echo "==> building the current binary"
CGO_ENABLED=0 go build -o "$WORK/cardinal" ./cmd/cardinal

echo "==> starting PostgreSQL"
docker network create "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" \
  -e POSTGRES_USER=cardinal -e POSTGRES_PASSWORD="$PGPASS" -e POSTGRES_DB=cardinal \
  postgres:19beta2 >/dev/null
for _ in $(seq 1 60); do
  docker exec "$PG" pg_isready -U cardinal -d cardinal >/dev/null 2>&1 && break
  sleep 1
done

echo "==> migrating with the build in this checkout"
docker run --rm --network "$NET" -v "$WORK/cardinal:/cardinal:ro" \
  alpine /cardinal migrate -dsn "$DSN"

applied=$(docker exec "$PG" psql -U cardinal -d cardinal -tAc \
  "SELECT count(*) FROM schema_migrations")
if [ "${ROLLBACK_CHECK_SABOTAGE:-}" = "1" ]; then
  docker exec "$PG" psql -U cardinal -d cardinal -q -c \
    "UPDATE schema_migrations SET breaking = 'sabotage: pretend this dropped a column' WHERE name = '0031_erasure_comment.sql'" >/dev/null
  echo "    SABOTAGE: 0031 marked breaking"
fi
echo "    $applied migrations applied"

failures=0
for version in "${VERSIONS[@]}"; do
  echo
  echo "==> $version against that schema"
  image="londerbe/cardinal:$version"
  docker pull -q "$image" >/dev/null

  # How far behind it is, from the tag rather than from the image: the
  # published images are distroless and have no shell to ask, and the
  # migrations are embedded in the binary rather than sitting on disk.
  #
  # A release whose schema matches the current one proves nothing — 0.3.0 and
  # 0.3.1 are such a pair — so that is a skip with a reason, not a pass.
  theirs=$(git ls-tree -r --name-only "v$version" migrations/ 2>/dev/null | grep -c '\.sql$' || echo 0)
  echo "    $version ships $theirs migrations, database has $applied"
  if [ "$theirs" -ge "$applied" ]; then
    echo "    SKIP: same schema as the current build, so this would exercise nothing"
    continue
  fi

  docker rm -f "$APP" >/dev/null 2>&1 || true
  docker run -d --name "$APP" --network "$NET" -p 8477:8080 \
    -v "$WORK/cardinal.toml:/etc/cardinal/cardinal.toml:ro" \
    "$image" serve -config /etc/cardinal/cardinal.toml >/dev/null

  ok=0
  for _ in $(seq 1 30); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8477/healthz)" = "200" ]; then
      ok=1
      break
    fi
    docker inspect -f '{{.State.Running}}' "$APP" 2>/dev/null | grep -q true || break
    sleep 1
  done

  logs=$(docker logs "$APP" 2>&1 || true)

  if [ "$ok" != "1" ]; then
    echo "    FAIL: $version did not serve against a schema this build migrated."
    echo "          Rolling back to it would not work. Its output:"
    echo "$logs" | sed 's/^/          /' | tail -20
    failures=$((failures + 1))
    continue
  fi
  echo "    serves /healthz"

  # The point of the whole exercise: it saw migrations it does not know and
  # carried on. Without this, a build that never looked would pass too.
  #
  # Only asked of releases that can answer. Drift detection arrived with
  # SchemaAhead in 0.2.0, so 0.1.0 serves against a newer schema without ever
  # noticing — which is the correct behaviour for a build that predates the
  # feature, and would be a false failure to demand otherwise. Asked of the tag
  # rather than hardcoded, so this stays right as releases accumulate.
  if git show "v$version:internal/store/migrate.go" 2>/dev/null | grep -q "SchemaAhead"; then
    if echo "$logs" | grep -qi "newer than this build"; then
      echo "    noticed the schema is ahead of it, and served anyway"
    else
      echo "    FAIL: $version has drift detection but never reported the schema"
      echo "          as ahead. Either it stopped working, or this release is not"
      echo "          actually behind the current schema and proves nothing."
      failures=$((failures + 1))
    fi
  else
    echo "    serves blind: this release predates drift detection (added in 0.2.0)"
  fi
done

echo
if [ "$failures" -ne 0 ]; then
  echo "rollback check FAILED for $failures release(s)"
  exit 1
fi
echo "rollback check passed: every release tested serves against the current schema"
