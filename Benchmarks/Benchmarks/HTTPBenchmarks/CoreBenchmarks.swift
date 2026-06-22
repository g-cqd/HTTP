//
//  CoreBenchmarks.swift
//  HTTPBenchmarks
//
//  HTTPCore — the byte-level hot paths (the prime SIMD/SWAR targets) and the field collection.
//

import Benchmark
import HTTPCore

func registerCoreBenchmarks() {
    Benchmark("core/ByteReader/readSlice-to-CRLF") { benchmark in
        for _ in benchmark.scaledIterations {
            getRequestBytes.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(reader.readSlice(until: 0x0D))
            }
        }
    }

    Benchmark("core/FieldValidation/isToken") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(FieldValidation.isToken(sampleFieldName))
        }
    }

    Benchmark("core/FieldValidation/isValidFieldValue") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(FieldValidation.isValidFieldValue(sampleFieldValue))
        }
    }

    Benchmark("core/HTTPFieldName/parse-mixed-case") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(HTTPFieldName("Content-Type"))
        }
    }

    Benchmark("core/HTTPFieldName/validating-bytes") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(HTTPFieldName(validating: sampleFieldName))
        }
    }

    Benchmark("core/HTTPFields/append+lookup") { benchmark in
        for _ in benchmark.scaledIterations {
            var fields = HTTPFields()
            fields.append("example.com", for: .host)
            fields.append("text/html; charset=utf-8", for: .contentType)
            fields.append("gzip, br", for: .acceptEncoding)
            blackHole(fields[.contentType])
            blackHole(fields.count(for: .host))
        }
    }

    Benchmark("core/HTTPFields/contentLength") { benchmark in
        var fields = HTTPFields()
        fields.append("12345", for: .contentLength)
        for _ in benchmark.scaledIterations {
            blackHole(fields.contentLength)
        }
    }

    // The canonical HPACK/QPACK Huffman code (RFC 7541 §5.2 / App. B) — the bit-level codec shared by
    // HTTP/2 and HTTP/3 header compression, and a prime SIMD/SWAR candidate.
    Benchmark("core/Huffman/encode") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(Huffman.encode(sampleFieldValue))
        }
    }

    Benchmark("core/Huffman/decode") { benchmark in
        let encoded = Huffman.encode(sampleFieldValue)
        for _ in benchmark.scaledIterations {
            encoded.withUnsafeBytes { raw in
                blackHole(try? Huffman.decode(raw.bytes))
            }
        }
    }
}
