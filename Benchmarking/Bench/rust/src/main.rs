//! rust-bench — hyper + tokio HTTP baseline for the consolidated battletest.
//!
//! A minimal idiomatic hyper 1.x server on the multi-threaded tokio runtime, serving the shared parity
//! route set (/, /json, /payload, /hello/<name>, POST /echo, /health) so every server runs an identical
//! workload under the same load generator. Each connection is served on its own task. Port from argv[1]
//! (default 8086).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::LazyLock;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

/// 32 × 32 B = 1024 B of compressible text, built once.
static PAYLOAD: LazyLock<Bytes> =
    LazyLock::new(|| Bytes::from("from-scratch swift http server. ".repeat(32)));

fn respond(content_type: &str, body: Bytes) -> Response<Full<Bytes>> {
    Response::builder()
        .header("Content-Type", content_type)
        .body(Full::new(body))
        .unwrap()
}

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    // POST /echo: read the request body and echo it back verbatim.
    if req.method() == Method::POST && req.uri().path() == "/echo" {
        let bytes = req
            .into_body()
            .collect()
            .await
            .map(|c| c.to_bytes())
            .unwrap_or_default();
        return Ok(respond("application/json", bytes));
    }

    let path = req.uri().path();
    let response = match path {
        "/" => respond("text/plain; charset=utf-8", Bytes::from_static(b"Hello from the Rust baseline.\n")),
        "/health" => respond("text/plain; charset=utf-8", Bytes::from_static(b"OK\n")),
        "/json" => respond("application/json", Bytes::from_static(b"{\"message\":\"Hello, World!\"}")),
        "/payload" => respond("text/plain; charset=utf-8", PAYLOAD.clone()),
        p if p.starts_with("/hello/") => {
            let name = &p["/hello/".len()..];
            let greeting = req
                .uri()
                .query()
                .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("greeting=")))
                .unwrap_or("Hello");
            respond("text/plain; charset=utf-8", Bytes::from(format!("{greeting}, {name}!\n")))
        }
        _ => Response::builder()
            .status(404)
            .body(Full::new(Bytes::from_static(b"Not Found")))
            .unwrap(),
    };
    Ok(response)
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8086);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr).await.expect("bind failed");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        let io = TokioIo::new(stream);
        tokio::task::spawn(async move {
            let _ = http1::Builder::new()
                .serve_connection(io, service_fn(handle))
                .await;
        });
    }
}
