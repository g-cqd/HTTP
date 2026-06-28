//! rust-bench — hyper + tokio HTTP baseline for the consolidated battletest.
//!
//! A minimal idiomatic hyper 1.x server on the multi-threaded tokio runtime, accepting connections in
//! a loop and serving each on its own task — mirroring the other servers' routes (`/`, `/health`) so
//! the comparison is a same-workload, same-load-generator test. Port comes from argv[1] (default 8086).

use std::convert::Infallible;
use std::net::SocketAddr;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = match req.uri().path() {
        "/" => Bytes::from_static(b"Hello from the Rust baseline.\n"),
        "/health" => Bytes::from_static(b"OK\n"),
        _ => {
            return Ok(Response::builder()
                .status(404)
                .body(Full::new(Bytes::from_static(b"Not Found")))
                .unwrap());
        }
    };
    Ok(Response::builder()
        .header("Content-Type", "text/plain; charset=utf-8")
        .body(Full::new(body))
        .unwrap())
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
