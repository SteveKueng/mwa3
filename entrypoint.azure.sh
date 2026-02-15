#!/bin/sh

set -eu

NAME="MunkiWebAdmin"

# Azure App Service (zip deploy / Oryx) does not guarantee root access or
# availability of apt-get at runtime. Keep startup logic pure-Python.

# Run migrations in two phases to avoid syncdb FK ordering issues.
python manage.py migrate --noinput
python manage.py migrate --noinput --run-syncdb

python manage.py collectstatic --noinput

# Azure provides the port via $PORT (or sometimes WEBSITES_PORT).
PORT_TO_BIND="${PORT:-${WEBSITES_PORT:-8000}}"

echo "Starting ${NAME} on 0.0.0.0:${PORT_TO_BIND}"

exec gunicorn --bind "0.0.0.0:${PORT_TO_BIND}" --timeout 600 --workers 4 munkiwebadmin.wsgi
