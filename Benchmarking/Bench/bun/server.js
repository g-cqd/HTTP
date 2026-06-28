// server.js — Bun.serve baseline for the consolidated battletest.
//
// Bun's native HTTP server (the `Bun.serve` fast path over its JavaScriptCore + zig I/O stack),
// implementing the shared parity route set (/, /json, /payload, /hello/<name>, POST /echo, /health) so
// every server runs an identical workload under the same load generator. Port from argv (default 8085).
const port = Number(process.argv[2] ?? 8085);
const payload = "from-scratch swift http server. ".repeat(32); // 32 × 32 B = 1024 B
const TEXT = { "Content-Type": "text/plain; charset=utf-8" };
const JSON_CT = { "Content-Type": "application/json" };

Bun.serve({
  port,
  hostname: "127.0.0.1",
  async fetch(req) {
    const url = new URL(req.url);
    const path = url.pathname;
    if (path === "/") return new Response("Hello from the Bun baseline.\n", { headers: TEXT });
    if (path === "/health") return new Response("OK\n", { headers: TEXT });
    if (path === "/json") return new Response('{"message":"Hello, World!"}', { headers: JSON_CT });
    if (path === "/payload") return new Response(payload, { headers: TEXT });
    if (path.startsWith("/hello/")) {
      const name = path.slice("/hello/".length);
      const greeting = url.searchParams.get("greeting") ?? "Hello";
      return new Response(`${greeting}, ${name}!\n`, { headers: TEXT });
    }
    if (path === "/echo" && req.method === "POST") {
      return new Response(await req.text(), { headers: JSON_CT });
    }
    return new Response("Not Found", { status: 404 });
  },
});
