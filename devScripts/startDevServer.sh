#!/bin/bash

set -euo pipefail

export APPNAME='MunkiWebAdmin'
export TIME_ZONE='Europe/Zurich'
export LANGUAGE_CODE='en-us'
export ALLOWED_HOSTS='localhost 127.0.0.1 [::1]'
export DEBUG=1

# On macOS, install Munki and point MUNKITOOLS_DIR to its Python client code.
# The Munki package installs to /usr/local/munki by default.
export MUNKITOOLS_DIR="${MUNKITOOLS_DIR:-/usr/local/munki}"

# Default to a local filesystem Munki repo in /Users/Shared.
export MUNKI_REPO_URL="${MUNKI_REPO_URL:-file:///Users/Shared/munkirepo}"
export MUNKI_REPO_PLUGIN="${MUNKI_REPO_PLUGIN:-FileRepo}"

# Ensure the local repo exists for FileRepo.
repo_path="${MUNKI_REPO_URL#file:///}"
mkdir -p "$repo_path" || true

python manage.py migrate --noinput

# Start the development server
python manage.py runserver