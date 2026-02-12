import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "munkiwebadmin.settings")


def _maybe_run_migrations_on_startup() -> None:
	# Some environments (Azure App Service Oryx zip deploy) start gunicorn
	# directly and do not run our entrypoint scripts. If using SQLite in the
	# extracted /tmp app directory, the DB can be empty on each restart.
	#
	# Run migrations automatically on Azure to avoid "no such table" errors.
	if not os.getenv("WEBSITE_INSTANCE_ID"):
		return
	if os.getenv("AUTO_MIGRATE_ON_STARTUP", "1") not in {"1", "true", "True"}:
		return

	try:
		import fcntl
		import django
		from django.core.management import call_command
	except Exception:
		return

	lock_path = os.getenv("MIGRATE_LOCK_FILE", "/tmp/mwa_migrate.lock")
	try:
		with open(lock_path, "w") as lock_file:
			fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
			django.setup()
			call_command("migrate", interactive=False)
	except Exception:
		# Never prevent the app from starting because of migrations.
		return


_maybe_run_migrations_on_startup()

application = get_wsgi_application()


