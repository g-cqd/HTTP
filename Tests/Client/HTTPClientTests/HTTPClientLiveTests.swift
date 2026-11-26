//
//  HTTPClientLiveTests.swift
//  HTTPClientTests
//
//  Opt-in (HTTP_CLIENT_LIVE=1) internet smoke tests: real TLS 1.3 handshakes against public origins
//  with RSA (developer.apple.com) and ECDSA (api.github.com) server certificates chained to the
//  platform PEM bundle, conditional GETs (304), and response decoding.
//

import Foundation
import HTTPCore
import HTTPTestSupport
import Testing

@testable import HTTPClient

@Suite(
    "HTTPClient — live origins (HTTP_CLIENT_LIVE=1)",
    .realNetwork,
    .enabled(if: ProcessInfo.processInfo.environment["HTTP_CLIENT_LIVE"] == "1")
)
struct HTTPClientLiveTests {
    @Test("fetches Apple DocC JSON over TLS 1.3 and revalidates it with If-None-Match")
    func appleDeveloperDocumentation() async throws {
        let client = HTTPClient()
        let url = "https://developer.apple.com/tutorials/data/documentation/swiftui.json"
        let first = try await client.get(url)
        #expect(first.status == .ok)
        #expect(first.body.starts(with: Array("{".utf8)))
        let etag = try #require(first.headerFields[.etag])
        var headers = HTTPFields()
        _ = headers.append(etag, for: .ifNoneMatch)
        let second = try await client.get(url, headers: headers)
        #expect(second.status == .notModified)
        await client.shutdown()
    }

    @Test("fetches GitHub API and raw content over TLS 1.3")
    func gitHub() async throws {
        let client = HTTPClient()
        let api = try await client.get("https://api.github.com/repos/swiftlang/swift-evolution")
        #expect(api.status == .ok)
        let raw = try await client.get(
            "https://raw.githubusercontent.com/swiftlang/swift-evolution/main/README.md"
        )
        #expect(raw.status == .ok && !raw.body.isEmpty)
        await client.shutdown()
    }
}
