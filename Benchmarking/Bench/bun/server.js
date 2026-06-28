// server.js — Bun.serve baseline for the consolidated battletest.
//
// Bun's native HTTP server (the `Bun.serve` fast path over its JavaScriptCore + zig I/O stack),
// mirroring the other servers' routes (`/`, `/health`) so the comparison is a same-workload,
// same-load-generator test. Port comes from argv (default 8085).
const port = Number(process.argv[2] ?? 8085);

Bun.serve({
  port,
  hostname: "127.0.0.1",
  fetch(req) {
    const path = new URL(req.url).pathname;
    if (path === "/") {
      return new Response("Hello from the Bun baseline.\n", {
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      });
    }
    if (path === "/health") {
      return new Response("OK\n", {
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      });
    }
    return new Response("Not Found", { status: 404 });
  },
});
