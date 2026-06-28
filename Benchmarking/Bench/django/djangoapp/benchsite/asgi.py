"""ASGI entrypoint — served by uvicorn (`benchsite.asgi:application`)."""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "benchsite.settings")
application = get_asgi_application()
