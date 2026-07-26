#!/usr/bin/env sh
# Rebuild and restart the bot, stamping the running image with the commit it
# was built from. Without this the image still runs fine — /version just
# can't tell you which commit it is.
set -e

cd "$(dirname "$0")"

if git rev-parse --git-dir >/dev/null 2>&1; then
    GIT_SHA="$(git rev-parse --short HEAD)"
    # A dirty tree means the image doesn't match the commit — say so rather
    # than reporting a sha that isn't what's actually running.
    if ! git diff-index --quiet HEAD -- 2>/dev/null; then
        GIT_SHA="${GIT_SHA}-dirty"
    fi
else
    GIT_SHA="unknown"
fi
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%MZ)"

export GIT_SHA BUILD_DATE
echo "Building ${GIT_SHA} (${BUILD_DATE})"

docker compose up -d --build "$@"

echo "Started. Check /version or /status in Telegram."
