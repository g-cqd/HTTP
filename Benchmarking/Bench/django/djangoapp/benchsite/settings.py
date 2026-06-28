"""
settings.py — benchsite

Minimal Django settings tuned for a fair, production-shaped benchmark against the Swift HTTP server:

  * DEBUG = False           — DEBUG=True is far slower and leaks memory; never benchmark with it on.
  * No database, no apps    — the scenarios are pure request/response; nothing here touches an ORM.
  * MIDDLEWARE is toggled   — BENCH_MIDDLEWARE=1 installs a realistic response-shaping chain that
                              mirrors the Swift server's chain; unset/0 runs an empty chain (floor).

Served two ways by run.sh: gunicorn (WSGI, sync views) and uvicorn (ASGI, async views) — see urls.py.
"""

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A fixed throwaway key — this app stores nothing and signs nothing that outlives the benchmark.
SECRET_KEY = "benchmark-only-not-a-secret"  # noqa: S105
DEBUG = False
ALLOWED_HOSTS = ["*"]  # loopback only; DEBUG=False otherwise rejects every Host.

ROOT_URLCONF = "benchsite.urls"
WSGI_APPLICATION = "benchsite.wsgi.application"
ASGI_APPLICATION = "benchsite.asgi.application"

# Nothing here needs an app, a template, or a database. Keeping these empty removes per-request work
# (auth, sessions, contenttypes) that would otherwise tax every request and muddy the comparison.
INSTALLED_APPS: list[str] = []
TEMPLATES: list[dict] = []
DATABASES: dict[str, dict] = {}

# A request hits an exact path (`/json`, `/echo`, …); never let CommonMiddleware issue a slash-append
# redirect, which would turn a benchmark request into a 301.
APPEND_SLASH = False

USE_I18N = False
USE_TZ = True
DEFAULT_CHARSET = "utf-8"

# BENCH_MIDDLEWARE=1 → a realistic chain mirroring the Swift server's (gzip, security headers, a CORS
# header, conditional-GET short-circuit, and CommonMiddleware). Otherwise an empty chain: the floor.
if os.environ.get("BENCH_MIDDLEWARE") == "1":
    MIDDLEWARE = [
        "django.middleware.security.SecurityMiddleware",  # ↔ SecurityHeadersMiddleware
        "django.middleware.gzip.GZipMiddleware",  # ↔ CompressionMiddleware (gzip)
        "django.middleware.common.CommonMiddleware",  # Content-Length, etc.
        "django.middleware.http.ConditionalGetMiddleware",  # ↔ ConditionalRequestMiddleware
        "benchsite.middleware.cors_middleware",  # ↔ CORSMiddleware
    ]
else:
    MIDDLEWARE = []
