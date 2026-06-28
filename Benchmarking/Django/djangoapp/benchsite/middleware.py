"""
middleware.py — benchsite

A tiny CORS middleware mirroring the Swift server's CORSMiddleware (it adds an `Access-Control-Allow-
Origin` header to every response). Written sync-and-async aware via `sync_and_async_middleware` so that
under ASGI/uvicorn it stays on the async path instead of being wrapped in a thread by Django — keeping
the async run a fair test of the async stack. Dependency-free (no django-cors-headers) on purpose.
"""

import asyncio

from django.utils.decorators import sync_and_async_middleware


@sync_and_async_middleware
def cors_middleware(get_response):
    if asyncio.iscoroutinefunction(get_response):

        async def middleware(request):
            response = await get_response(request)
            response["Access-Control-Allow-Origin"] = "*"
            return response

    else:

        def middleware(request):
            response = get_response(request)
            response["Access-Control-Allow-Origin"] = "*"
            return response

    return middleware
