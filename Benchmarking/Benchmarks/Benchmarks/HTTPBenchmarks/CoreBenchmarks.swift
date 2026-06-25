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

    // The same validator over a realistic long value (~198 B) — the size that decides whether a
    // SWAR (8 B/word) rewrite beats the per-byte scan.
    Benchmark("core/FieldValidation/isValidFieldValue-long") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(FieldValidation.isValidFieldValue(longFieldValue))
        }
    }

    // The request-target / pseudo-header validator over a realistic long `:path` (~140 B) — runs on
    // every HTTP/2 pseudo-header, so the SWAR rewrite pays off here.
    Benchmark("core/FieldValidation/isRequestTargetValue-long") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(FieldValidation.isRequestTargetValue(longRequestTarget))
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

    registerStructuredFieldBenchmarks()
}

/// RFC 8941 Structured Fields parser benchmarks — parsing an untrusted header value is the hot path.
///
/// The substrate for RFC 9218 Priority and other SF headers; extracted from
/// ``registerCoreBenchmarks()`` so that registration stays under the cyclomatic-complexity cap.
private func registerStructuredFieldBenchmarks() {
    Benchmark("core/StructuredFields/parseItem") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(try? StructuredFields.parseItem(structuredFieldItem))
        }
    }

    Benchmark("core/StructuredFields/parseList") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(try? StructuredFields.parseList(structuredFieldList))
        }
    }

    Benchmark("core/StructuredFields/parseDictionary") { benchmark in
        for _ in benchmark.scaledIterations {
            blackHole(try? StructuredFields.parseDictionary(structuredFieldDictionary))
        }
    }
}

/// A Structured Fields *item* with parameters (an integer plus a token and a boolean parameter).
private let structuredFieldItem = "42;importance=high;fresh=?1"

/// A Structured Fields *list*: tokens, a decimal parameter, and a parameterized inner list (§3.1).
private let structuredFieldList = "gzip, deflate;q=0.5, (a b);n=2"

/// A Structured Fields *dictionary* shaped like an RFC 9218 Priority header plus a string value.
private let structuredFieldDictionary = "u=3, i, lang=\"en\""
