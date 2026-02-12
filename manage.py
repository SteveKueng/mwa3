#!/usr/bin/env python
import os
import sys


def _run_migrate_if_needed(argv: list[str]) -> None:
    # Only do this for createsuperuser to avoid surprising behavior for other
    # management commands.
    if len(argv) < 2:
        return
    if argv[1] != "createsuperuser":
        return

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "munkiwebadmin.settings")

    try:
        import django
        from django.core.management import call_command
    except Exception:
        return

    django.setup()
    call_command("migrate", interactive=False)


if __name__ == "__main__":
    _run_migrate_if_needed(sys.argv)

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "munkiwebadmin.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)