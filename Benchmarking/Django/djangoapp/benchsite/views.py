"""
views.py — benchsite

Both a sync and an async implementation of each route. run.sh serves the sync set under gunicorn
(WSGI) and the async set under uvicorn (ASGI) — see urls.py, which picks the set from BENCH_ASYNC — so
each Django deployment model runs in its own idiom (sync def vs async def) rather than one being
emulated on top of the other.

The routes mirror ours-bench (Benchmarking/Django/ours) byte-for-byte in intent:
    GET  /            → "Hello, World!"             (framework floor)
    GET  /json        → {"message": "Hello, World!"} (serialize a dict)
    GET  /hello/<name>→ "<greeting>, <name>!"        (router + path/query params)
    POST /echo        → echo the parsed JSON body    (request read + JSON round-trip)
    GET  /payload     → ~1 KiB of text               (a body worth gzipping)
"""

import json

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

# Mirrors ours-bench: 32 × 32 bytes = 1024 bytes of compressible text.
PAYLOAD = "from-scratch swift http server. " * 32

_TEXT = "text/plain; charset=utf-8"


# --- sync (served under WSGI / gunicorn) ----------------------------------------------------------


def index(request):
    return HttpResponse("Hello, World!", content_type=_TEXT)


def json_view(request):
    return JsonResponse({"message": "Hello, World!"})


def hello(request, name):
    greeting = request.GET.get("greeting", "Hello")
    return HttpResponse(f"{greeting}, {name}!", content_type=_TEXT)


@csrf_exempt
def echo(request):
    data = json.loads(request.body)
    return JsonResponse(data, safe=False)


def payload(request):
    return HttpResponse(PAYLOAD, content_type=_TEXT)


# --- async (served under ASGI / uvicorn) ----------------------------------------------------------


async def aindex(request):
    return HttpResponse("Hello, World!", content_type=_TEXT)


async def ajson(request):
    return JsonResponse({"message": "Hello, World!"})


async def ahello(request, name):
    greeting = request.GET.get("greeting", "Hello")
    return HttpResponse(f"{greeting}, {name}!", content_type=_TEXT)


@csrf_exempt
async def aecho(request):
    data = json.loads(request.body)
    return JsonResponse(data, safe=False)


async def apayload(request):
    return HttpResponse(PAYLOAD, content_type=_TEXT)
