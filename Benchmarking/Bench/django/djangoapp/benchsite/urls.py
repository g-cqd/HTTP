"""
urls.py — benchsite

Maps the benchmark routes to either the sync or the async view set, chosen by BENCH_ASYNC so the WSGI
run uses `def` views and the ASGI run uses `async def` views. Patterns carry no trailing slash so they
match the exact paths the load generator hits (`/json`, `/echo`, …) with APPEND_SLASH off.
"""

import os

from django.urls import path

from . import views

if os.environ.get("BENCH_ASYNC") == "1":
    _index, _json, _hello, _echo, _payload = (
        views.aindex,
        views.ajson,
        views.ahello,
        views.aecho,
        views.apayload,
    )
else:
    _index, _json, _hello, _echo, _payload = (
        views.index,
        views.json_view,
        views.hello,
        views.echo,
        views.payload,
    )

urlpatterns = [
    path("", _index),
    path("json", _json),
    path("hello/<str:name>", _hello),
    path("echo", _echo),
    path("payload", _payload),
]
