//
//  HTTP1Benchmarks.swift
//  HTTPBenchmarks
//
//  HTTP/1.1 (RFC 9112) — request-line, header, full-request, and chunked parsers, plus the response
//  serializer. Each parse runs over a fresh zero-copy `ByteReader` borrowing a fixture buffer.
//

import Benchmark
import HTTP1
import HTTPCore

func registerHTTP1Benchmarks() {
    Benchmark("http1/RequestLineParser/parse") { benchmark in
        for _ in benchmark.scaledIterations {
            requestLineBytes.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(try? RequestLineParser.parse(&reader))
            }
        }
    }

    Benchmark("http1/HeaderParser/parse") { benchmark in
        for _ in benchmark.scaledIterations {
            headerBlockBytes.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(try? HeaderParser.parse(&reader, limits: .default))
            }
        }
    }

    Benchmark("http1/RequestParser/get") { benchmark in
        for _ in benchmark.scaledIterations {
            getRequestBytes.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(try? RequestParser.parse(&reader, limits: .default))
            }
        }
    }

    // A realistic browser GET (~11 header fields, long values) — the HTTP/1.1 server's real
    // per-request parse cost (request line + header scan + field validation + HTTPFields build),
    // unlike the tiny `get` fixture above.
    Benchmark("http1/RequestParser/realistic") { benchmark in
        for _ in benchmark.scaledIterations {
            realisticHTTP1Request.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(try? RequestParser.parse(&reader, limits: .default))
            }
        }
    }

    Benchmark("http1/RequestParser/post-content-length") { benchmark in
        for _ in benchmark.scaledIterations {
            postRequestBytes.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(try? RequestParser.parse(&reader, limits: .default))
            }
        }
    }

    Benchmark("http1/RequestParser/post-chunked") { benchmark in
        for _ in benchmark.scaledIterations {
            chunkedRequestBytes.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(try? RequestParser.parse(&reader, limits: .default))
            }
        }
    }

    Benchmark("http1/ChunkedDecoder/decode") { benchmark in
        for _ in benchmark.scaledIterations {
            chunkedBodyBytes.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(try? ChunkedDecoder.decode(&reader, limits: .default))
            }
        }
    }

    Benchmark("http1/ResponseSerializer/serialize") { benchmark in
        var fields = HTTPFields()
        fields.append("text/plain; charset=utf-8", for: .contentType)
        fields.append("HTTPBench/1.0", for: .server)
        let response = HTTPResponse(status: .ok, headerFields: fields)
        let body = Array("Hello, world!".utf8)
        for _ in benchmark.scaledIterations {
            blackHole(ResponseSerializer.serialize(response, body: body))
        }
    }
}
