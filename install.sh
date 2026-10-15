#!/usr/bin/env bash
# Installs and starts QN-Sentry with one command (#18), on Linux, macOS or Git Bash:
#
#     ./install.sh
#
# 1. Checks that Docker is installed and running, with Docker Compose 2.24 or newer
# 2. Creates .env from .env.example with a generated database password and domain
#    verification secret. An existing .env is kept: only the example values are replaced
# 3. Builds and starts every service, and waits until the API answers
#
# With the secret the team already uses, the TXT records that were added keep working.
# Export it: on a line of its own, without export, the script does not see it
#
#     export DOMAIN_VERIFICATION_SECRET=<secret>
#     ./install.sh
#
# Running it again is safe: it keeps .env and updates the containers.
# Windows PowerShell: install.ps1 does the same.

set -euo pipefail

cd "$(dirname "$0")"

MIN_COMPOSE_MINOR=24 # 2.24: the version docs/installation.md requires
EXAMPLE_PASSWORD=change-me
EXAMPLE_SECRET=change-me-to-at-least-32-random-characters
HEALTH_URL=http://127.0.0.1:8000/api/health
WAIT_SECONDS=180

# Taken from the environment once: compose must not see it, .env is the only source
GIVEN_SECRET=${DOMAIN_VERIFICATION_SECRET:-}
unset DOMAIN_VERIFICATION_SECRET

step() { printf '\n==> %s\n' "$1"; }
note() { printf '    %s\n' "$1"; }
fail() {
    printf '\nError: %s\n' "$1" >&2
    exit 1
}

# ---------- 1. Requirements ----------

step "Checking the requirements"
command -v docker >/dev/null 2>&1 ||
    fail "Docker is not installed. Install Docker Desktop (Windows, macOS) or Docker Engine (Linux): https://docs.docker.com/get-docker/"
docker info >/dev/null 2>&1 ||
    fail "Docker is installed but not running, or this user may not use it. Start Docker Desktop; on Linux run 'sudo systemctl start docker' and add yourself to the docker group."
compose=$(docker compose version --short 2>/dev/null) ||
    fail "The Docker Compose plugin is missing: https://docs.docker.com/compose/install/"
# e.g. "2.29.7", "v2.24.0" or "2.30.3-desktop.1"
IFS=. read -r major minor _ <<<"${compose#v}"
minor=${minor%%[!0-9]*}
if [ "${major:-0}" -lt 2 ] || { [ "$major" -eq 2 ] && [ "${minor:-0}" -lt "$MIN_COMPOSE_MINOR" ]; }; then
    fail "Docker Compose $compose is too old: 2.$MIN_COMPOSE_MINOR or newer is needed (update Docker Desktop or the compose plugin)."
fi
note "Docker $(docker version --format '{{.Server.Version}}'), Docker Compose $compose"
# Checked before .env is touched. Spaces, quotes or # would be read differently from .env
if [ -n "$GIVEN_SECRET" ] && ! [[ $GIVEN_SECRET =~ ^[^[:space:]#\"\']{32,}$ ]]; then
    fail "DOMAIN_VERIFICATION_SECRET must be at least 32 characters, without spaces, quotes or #."
fi

# ---------- 2. Configuration ----------

random_hex() {
    # The operating system's cryptographic random generator
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$1"
    else
        od -An -tx1 -N"$1" /dev/urandom | tr -d ' \n'
    fi
}

get_value() {
    awk -F= -v key="$1" '$1 == key { sub(/^[^=]*=/, ""); sub(/\r$/, ""); print; exit }' .env
}

set_value() {
    local tmp
    tmp=$(mktemp)
    awk -v key="$1" -v value="$2" '
        { line = $0; sub(/\r$/, "", line) }
        index(line, key "=") == 1 { print key "=" value; done = 1; next }
        { print }
        END { if (!done) print key "=" value }
    ' .env >"$tmp"
    cat "$tmp" >.env # keeps the permissions of .env
    rm -f "$tmp"
}

# The database volume of an earlier installation: its password is the one in that .env.
# The project name is the folder name, as Docker Compose makes it
project=${COMPOSE_PROJECT_NAME:-$(basename "$PWD" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')}
database_exists() {
    [ -n "$(docker volume ls -q \
        --filter "label=com.docker.compose.project=$project" \
        --filter "label=com.docker.compose.volume=db-data")" ]
}

step "Preparing the configuration (.env)"
if [ ! -f .env ]; then
    if database_exists; then
        fail "There is no .env, but the database of an earlier installation still exists, and it only accepts the password of that .env. Put the old .env back, or delete all clients, scans and findings with 'docker compose down -v' and run this script again."
    fi
    cp .env.example .env
    chmod 600 .env 2>/dev/null || true
    note "Created .env from .env.example"
else
    note "Keeping the existing .env"
fi

password=$(get_value POSTGRES_PASSWORD)
if [ -z "$password" ] || [ "$password" = "$EXAMPLE_PASSWORD" ]; then
    if database_exists; then
        # The database was made with this password: a new one would lock the services out
        note "Warning: the database still uses the example password. Leaving it, since a new one would not match the existing database."
    else
        set_value POSTGRES_PASSWORD "$(random_hex 24)"
        note "Generated a database password"
    fi
fi

secret=$(get_value DOMAIN_VERIFICATION_SECRET)
if [ -z "$secret" ] || [ "$secret" = "$EXAMPLE_SECRET" ]; then
    if [ -n "$GIVEN_SECRET" ]; then
        set_value DOMAIN_VERIFICATION_SECRET "$GIVEN_SECRET"
        note "Using the DOMAIN_VERIFICATION_SECRET that was given"
    else
        set_value DOMAIN_VERIFICATION_SECRET "$(random_hex 32)"
        note "Generated a new DOMAIN_VERIFICATION_SECRET: every domain needs the TXT record the"
        note "dashboard shows for it. To keep the records the team already added, put the team's"
        note "secret in .env instead and run this script again."
    fi
elif [ -n "$GIVEN_SECRET" ] && [ "$GIVEN_SECRET" != "$secret" ]; then
    note "Warning: .env already has another DOMAIN_VERIFICATION_SECRET. Keeping it: changing it"
    note "would invalidate every TXT record. Edit .env yourself if you really want to replace it."
fi

# ---------- 3. Start ----------

step "Building and starting QN-Sentry (the first build takes a few minutes)"
if ! docker compose up -d --build; then
    docker compose logs --tail 20 migrate api 2>/dev/null || true
    fail "Not everything could be started; the last lines of the logs are above. A port already in use is the most common cause: see 'Ports already in use' in docs/installation.md."
fi

api_healthy() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 5 "$HEALTH_URL" 2>/dev/null | grep -q '"database":"ok"'
    else
        docker compose exec -T api python -c \
            "import urllib.request; assert b'\"database\":\"ok\"' in urllib.request.urlopen('$HEALTH_URL', timeout=5).read()" \
            >/dev/null 2>&1
    fi
}

step "Waiting for the API"
waited=0
until api_healthy; do
    if [ "$waited" -ge "$WAIT_SECONDS" ]; then
        docker compose logs --tail 20 api 2>/dev/null || true
        fail "The API did not answer within $WAIT_SECONDS seconds; the last lines of its log are above."
    fi
    sleep 3
    waited=$((waited + 3))
done

step "QN-Sentry is running"
note "Dashboard: http://localhost:8080"
note "API:       http://localhost:8000/api/health"
note ""
note ".env holds the database password and the verification secret: keep a copy in a"
note "password manager and never commit it. Next: docs/user-guide.md"
note "Stop with 'docker compose down'; your data is kept."
