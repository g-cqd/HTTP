//
//  FileResponderNegotiationTests.swift
//  HTTPServerTests
//
//  RFC 9110 §12.5.5 / §15.4.5 — `Vary` tells a cache which request headers select the representation,
//  so it must be identical on the `304` and on the `200` it revalidates. A cache that stored the 200
//  under `Vary: Accept-Encoding` and is then handed a `Vary`-less `304` has been told the resource is
//  no longer negotiated, and may hand the stored Brotli bytes to a client that never asked for them
//  (§15.4.5 lists `Vary` among the fields a 304 MUST carry when the 200 would have).
//

import Foundation
import HTTPCore
import Testing

@testable import HTTPServer

@Suite("FileResponder — content negotiation invariants (RFC 9110 §12.5)")
struct FileResponderNegotiationTests {
    private func get(_ path: String, headers: [(HTTPFieldName, String)] = []) -> HTTPRequest {
        var fields = HTTPFields()
        for (name, value) in headers {
            _ = fields.append(value, for: name)
        }
        return HTTPRequest(
            method: .get, scheme: "https", authority: "x", path: path, headerFields: fields
        )
    }

    /// Creates a temp tree and runs `body` against a responder rooted there.
    private func withTree(
        _ files: [String: [UInt8]],
        precompressed: Bool = true,
        _ body: (FileResponder) async -> Void
    ) async {
        let manager = FileManager.default
        let root = manager.temporaryDirectory
            .appendingPathComponent("filenegotiation-\(UUID().uuidString)")
        try? manager.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: root) }
        FileTree.write(files, into: root)
        await body(FileResponder(root: root.path, precompressed: precompressed))
    }

    /// The 200 for `path` under `accept`, then the 304 its own `ETag` revalidates into.
    private func pair(
        _ responder: FileResponder,
        _ path: String,
        accept: String
    ) async -> (ok: ServerResponse, notModified: ServerResponse) {
        let headers = [(HTTPFieldName.acceptEncoding, accept)]
        let ok = await responder.respond(to: get(path, headers: headers), body: [])
        let tag = ok.head.headerFields[.etag] ?? ""
        let revalidate = get(path, headers: headers + [(.ifNoneMatch, tag)])
        return (ok, await responder.respond(to: revalidate, body: []))
    }

    @Test(
        "a precompressed 304 carries the same Vary as its 200 (RFC 9110 §15.4.5)",
        arguments: ["br", "gzip", "identity", ""]
    )
    func varyIsInvariantAcrossStatuses(_ accept: String) async {
        let files = ["a.css": Array("body{}".utf8), "a.css.br": Array("BR".utf8)]
        await withTree(files) { responder in
            let both = await pair(responder, "/a.css", accept: accept)
            #expect(both.ok.head.status == .ok)
            #expect(both.notModified.head.status == .notModified)
            #expect(
                both.notModified.head.headerFields.values(for: .vary)
                    == both.ok.head.headerFields.values(for: .vary))
            #expect(both.ok.head.headerFields[.vary]?.contains("Accept-Encoding") == true)
        }
    }

    @Test("the 200 advertises Vary even when this request got no sidecar")
    func varyAdvertisedWithoutASidecar() async {
        // No sidecar exists at all, but the resource is still negotiated: a cache that stores this
        // identity copy without `Vary` would replay it to a Brotli-capable client once one appears.
        await withTree(["a.css": Array("body{}".utf8)]) { responder in
            let response = await responder.respond(to: get("/a.css"), body: [])
            #expect(response.head.headerFields[.vary]?.contains("Accept-Encoding") == true)
            #expect(response.head.headerFields[.contentEncoding] == nil)
        }
    }

    @Test("a resource that is never negotiated advertises no Vary")
    func noVaryWhenNotNegotiated() async {
        // Precompression disabled: the representation cannot vary, so claiming it does would only
        // fragment every downstream cache key for nothing.
        await withTree(["a.css": Array("body{}".utf8)], precompressed: false) { responder in
            let response = await responder.respond(to: get("/a.css"), body: [])
            #expect(response.head.headerFields[.vary] == nil)
        }
        // An already-compressed media type is never given a sidecar either.
        await withTree(["a.png": Array("PNG".utf8)]) { responder in
            let response = await responder.respond(to: get("/a.png"), body: [])
            #expect(response.head.headerFields[.vary] == nil)
        }
    }

    @Test("the 304 keeps ETag and Last-Modified alongside Vary (RFC 9110 §15.4.5)")
    func notModifiedCarriesTheValidators() async {
        let files = ["a.css": Array("body{}".utf8), "a.css.br": Array("BR".utf8)]
        await withTree(files) { responder in
            let both = await pair(responder, "/a.css", accept: "br")
            let head = both.notModified.head
            #expect(head.headerFields[.etag] == both.ok.head.headerFields[.etag])
            #expect(head.headerFields[.lastModified] == both.ok.head.headerFields[.lastModified])
            #expect(both.notModified.body.isEmpty)
        }
    }

    // MARK: q-values (RFC 9110 §12.4.2, §12.5.3)

    /// A tree carrying the identity file plus both sidecars, so only negotiation decides the winner.
    private static let bothSidecars = [
        "a.css": Array("IDENTITY".utf8),
        "a.css.br": Array("BROTLI".utf8),
        "a.css.gz": Array("GZIP".utf8)
    ]

    /// The `Content-Encoding` and body the responder picks for `accept`.
    private func negotiate(
        _ responder: FileResponder,
        accept: String
    ) async -> (encoding: String?, body: [UInt8], status: HTTPStatus) {
        let request = get("/a.css", headers: [(.acceptEncoding, accept)])
        let response = await responder.respond(to: request, body: [])
        return (response.head.headerFields[.contentEncoding], response.body, response.head.status)
    }

    @Test(
        "every spelling of a zero quality refuses the coding (RFC 9110 §12.4.2)",
        arguments: [
            "br;q=0",
            "br;q=0.0",
            "br;q=0.00",
            "br;q=0.000",
            "br;Q=0",
            "br;Q=0.000",
            "br; q=0",
            "br ; q=0.0",
            "BR;q=0"
        ]
    )
    func zeroQualityRefusesTheCoding(_ accept: String) async {
        // Only the Brotli sidecar exists, so a coding that slipped through would be visible.
        let files = ["a.css": Array("IDENTITY".utf8), "a.css.br": Array("BROTLI".utf8)]
        await withTree(files) { responder in
            let result = await negotiate(responder, accept: accept)
            #expect(result.encoding == nil, "\(accept) was treated as acceptable")
            #expect(result.body == Array("IDENTITY".utf8))
        }
    }

    @Test(
        "the highest q wins, not a hardcoded Brotli preference (RFC 9110 §12.5.3)",
        arguments: [
            ("br;q=0.1, gzip;q=0.9", "gzip"),
            ("gzip;q=1.0, br;q=0.5", "gzip"),
            ("br;q=0.9, gzip;q=0.1", "br"),
            ("gzip;q=0.001, br;q=0.002", "br"),
            ("br;q=0, gzip", "gzip"),
            ("gzip;q=0, br", "br"),
            ("br, gzip", "br"),
            ("x-gzip;q=1, br;q=0.1", "gzip")
        ]
    )
    func highestQualityWins(_ accept: String, _ expected: String) async {
        await withTree(Self.bothSidecars) { responder in
            let result = await negotiate(responder, accept: accept)
            #expect(result.encoding == expected, "\(accept) chose \(result.encoding ?? "identity")")
        }
    }

    @Test(
        "a wildcard supplies a quality only where no explicit entry does",
        arguments: [
            ("*", "br"),
            ("*;q=1, br;q=0", "gzip"),
            ("*;q=0, br;q=1", "br"),
            ("*;q=0.5, gzip;q=0.9", "gzip")
        ]
    )
    func wildcardIsOnlyAFallback(_ accept: String, _ expected: String) async {
        await withTree(Self.bothSidecars) { responder in
            #expect(await negotiate(responder, accept: accept).encoding == expected)
        }
    }

    @Test(
        "a client that refuses identity and cannot be coded gets 406 (RFC 9110 §12.5.3, §15.5.7)",
        arguments: ["identity;q=0", "identity;q=0.000", "*;q=0", "IDENTITY;Q=0"]
    )
    func identityRefusedIsNotAcceptable(_ accept: String) async {
        await withTree(["a.css": Array("IDENTITY".utf8)]) { responder in
            let result = await negotiate(responder, accept: accept)
            #expect(result.status == .notAcceptable)
            #expect(result.body.isEmpty)
        }
    }

    @Test("refusing identity is fine when an accepted coding is actually available")
    func identityRefusedButCodedAvailable() async {
        await withTree(Self.bothSidecars) { responder in
            let result = await negotiate(responder, accept: "identity;q=0, br")
            #expect(result.status == .ok)
            #expect(result.encoding == "br")
            #expect(result.body == Array("BROTLI".utf8))
        }
    }

    @Test("a more specific identity entry overrides a zero wildcard (RFC 9110 §12.5.3)")
    func explicitIdentityBeatsZeroWildcard() async {
        await withTree(["a.css": Array("IDENTITY".utf8)]) { responder in
            let result = await negotiate(responder, accept: "*;q=0, identity;q=1")
            #expect(result.status == .ok)
            #expect(result.body == Array("IDENTITY".utf8))
        }
    }

    @Test(
        "a malformed weight makes the entry unusable rather than silently full quality",
        arguments: ["br;q=", "br;q=2", "br;q=1.5", "br;q=0.0000", "br;q=abc", "br;q=-1"]
    )
    func malformedWeightIsIgnored(_ accept: String) async {
        let files = ["a.css": Array("IDENTITY".utf8), "a.css.br": Array("BROTLI".utf8)]
        await withTree(files) { responder in
            let result = await negotiate(responder, accept: accept)
            #expect(result.encoding == nil, "\(accept) was honored as a valid weight")
        }
    }
}
