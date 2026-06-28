"""WSGI entrypoint — served by gunicorn (`benchsite.wsgi:application`)."""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "benchsite.settings")
application = get_wsgi_application()
