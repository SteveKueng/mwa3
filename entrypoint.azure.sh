#!/bin/sh

set -eu

NAME="MunkiWebAdmin"

# Ensure relative paths (manage.py, static, etc.) resolve even if the startup
# working directory isn't /home/site/wwwroot.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

if [ "${MWA_STARTUP_DEBUG:-0}" = "1" ]; then
	echo "[mwa] Startup debug enabled"
	echo "[mwa] PWD: $(pwd)"
	echo "[mwa] UID:GID: $(id -u):$(id -g)"
	echo "[mwa] Python: $(command -v python || true)"
	echo "[mwa] Gunicorn: $(command -v gunicorn || true)"
	echo "[mwa] Listing /home/site/wwwroot (if present):"
	ls -la /home/site/wwwroot 2>/dev/null || true
fi

# Install 7z if not present and allowed by environment.
if ! command -v 7z >/dev/null 2>&1; then
  echo "[mwa] 7z not found"
  if [ "${MWA_TRY_INSTALL_7Z:-0}" = "1" ] && command -v apt-get >/dev/null 2>&1 && [ "$(id -u)" = "0" ]; then
    echo "[mwa] Trying to install p7zip-full via apt-get"
    apt-get update && apt-get install -y --no-install-recommends p7zip-full || true
  fi
fi

# Azure App Service (zip deploy / Oryx) does not guarantee root access or
# availability of apt-get at runtime. Keep startup logic pure-Python.

# Run migrations in two phases to avoid syncdb FK ordering issues.
python manage.py migrate --noinput
python manage.py migrate --noinput --run-syncdb

python manage.py collectstatic --noinput

# Azure provides the port via $PORT (or sometimes WEBSITES_PORT).
PORT_TO_BIND="${PORT:-${WEBSITES_PORT:-8000}}"

echo "Starting ${NAME} on 0.0.0.0:${PORT_TO_BIND}"

exec python -m gunicorn --bind "0.0.0.0:${PORT_TO_BIND}" --timeout 600 --workers 4 munkiwebadmin.wsgi
