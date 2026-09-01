"""
views.py — benchsite

Both a sync and an async implementation of each route. run.sh serves the sync set under gunicorn
(WSGI) and the async set under uvicorn (ASGI) — see urls.py, which picks the set from BENCH_ASYNC — so
each Django deployment model runs in its own idiom (sync def vs async def) rather than one being
emulated on top of the other.

The routes mirror ours-bench (Benchmarking/Django/ours) byte-for-byte in intent:
    GET  /plaintext   → "Hello, World!"             (framework floor, byte-identical field-wide)
    GET  /health      → "OK\n"                       (the harness's readiness probe)
    GET  /json        → {"message":"Hello, World!"}  (serialize a small object)
    GET  /hello/<name>→ "<greeting>, <name>!"        (router + path/query params)
    POST /echo        → the request body, verbatim  (request read + body round-trip)
    GET  /payload     → ~1 KiB of text               (a body worth gzipping)
"""

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

# Mirrors ours-bench: 32 × 32 bytes = 1024 bytes of compressible text.
PAYLOAD = "from-scratch swift http server. " * 32

_TEXT = "text/plain; charset=utf-8"
_JSON = "application/json"
# The field answers /json with a COMPACT object. Django's JsonResponse defaults to ", "/": "
# separators, which made this server's body differ from every peer by two bytes — invisible to a
# status-code check, caught by the harness's byte-equivalence gate.
_JSON_BODY = '{"message":"Hello, World!"}'


# --- sync (served under WSGI / gunicorn) ----------------------------------------------------------


def index(request):
    return HttpResponse("Hello from the Django baseline.\n", content_type=_TEXT)


def health(request):
    return HttpResponse("OK\n", content_type=_TEXT)


def plaintext(request):
    return HttpResponse("Hello, World!", content_type=_TEXT)


def json_view(request):
    return HttpResponse(_JSON_BODY, content_type=_JSON)


def hello(request, name):
    greeting = request.GET.get("greeting", "Hello")
    return HttpResponse(f"{greeting}, {name}!\n", content_type=_TEXT)


@csrf_exempt
def echo(request):
    # Verbatim, like every peer. Parsing and re-serialising through JsonResponse rewrote the body
    # with ", "/": " separators, so this server echoed BACK different bytes than it was sent.
    return HttpResponse(request.body, content_type=_JSON)


def payload(request):
    return HttpResponse(PAYLOAD, content_type=_TEXT)


# --- async (served under ASGI / uvicorn) ----------------------------------------------------------


async def aindex(request):
    return HttpResponse("Hello from the Django baseline.\n", content_type=_TEXT)


async def ahealth(request):
    return HttpResponse("OK\n", content_type=_TEXT)


async def aplaintext(request):
    return HttpResponse("Hello, World!", content_type=_TEXT)


async def ajson(request):
    return HttpResponse(_JSON_BODY, content_type=_JSON)


async def ahello(request, name):
    greeting = request.GET.get("greeting", "Hello")
    return HttpResponse(f"{greeting}, {name}!\n", content_type=_TEXT)


@csrf_exempt
async def aecho(request):
    # Verbatim, like every peer — see `echo`.
    return HttpResponse(request.body, content_type=_JSON)


async def apayload(request):
    return HttpResponse(PAYLOAD, content_type=_TEXT)
