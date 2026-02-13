#!/bin/sh

NAME="MunkiWebAdmin"                          # Name of the application
DJANGODIR=/home/app/web                       # Django project directory
SOCKFILE=/home/app/gunicorn.sock              # we will communicte using this unix socket
USER=app                                      # the user to run as
GROUP=app                                     # the group to run as
NUM_WORKERS=3                                 # how many worker processes should Gunicorn spawn
DJANGO_SETTINGS_MODULE=munkiwebadmin.settings # which settings file should Django use

# mount azure blob storage 
if [ -n "${AZURE_STORAGE_BLOB_ENDPOINT:-}" ]; then
  blobfuse2 mount /munkirepo/
fi

echo "Waiting for postgres..."

sql_host="${DB_HOST:-db}"
sql_port="${DB_PORT:-5432}"

while ! nc -z "$sql_host" "$sql_port"; do
  sleep 0.2
done

echo "PostgreSQL started"

# migrate database
python manage.py migrate --noinput --run-syncdb

echo "Starting $NAME as $(whoami)"

export DJANGO_SETTINGS_MODULE=$DJANGO_SETTINGS_MODULE

# Start your Django Unicorn
gunicorn munkiwebadmin.wsgi:application \
  --name $NAME \
  --workers $NUM_WORKERS \
  --user=$USER --group=$GROUP \
  --bind=unix:$SOCKFILE \
  --log-level=warn \
  --log-file=/home/app/gunicorn.log \
  --daemon

exec nginx -g "daemon off;"
