//
//  HTTPStatusTests.swift
//  HTTPCoreTests
//
//  RED→GREEN driver for RFC 9110 §15 status codes and their classification.
//

import Testing

@testable import HTTPCore

@Suite("RFC 9110 §15 — HTTPStatus")
struct HTTPStatusTests {
    @Test("registered constants carry their numeric codes")
    func registeredConstants() {
        #expect(HTTPStatus.continue.code == 100)
        #expect(HTTPStatus.ok.code == 200)
        #expect(HTTPStatus.noContent.code == 204)
        #expect(HTTPStatus.movedPermanently.code == 301)
        #expect(HTTPStatus.notFound.code == 404)
        #expect(HTTPStatus.internalServerError.code == 500)
    }

    @Test(
        "classifies a code into its response class (RFC 9110 §15)",
        arguments: [
            (100, HTTPStatus.Kind.informational),
            (199, .informational),
            (200, .successful),
            (204, .successful),
            (299, .successful),
            (300, .redirection),
            (301, .redirection),
            (399, .redirection),
            (400, .clientError),
            (404, .clientError),
            (499, .clientError),
            (500, .serverError),
            (503, .serverError),
            (599, .serverError)
        ]
    )
    func classifies(_ code: Int, _ expected: HTTPStatus.Kind) {
        #expect(HTTPStatus(code: code)?.kind == expected)
    }

    @Test("rejects codes outside 100...599", arguments: [-1, 0, 1, 99, 600, 700, 999, 1_000])
    func rejectsInvalidCodes(_ code: Int) {
        #expect(HTTPStatus(code: code) == nil)
    }

    @Test("exposes the registered reason-phrase; unregistered codes have none (RFC 9110 §15)")
    func reasonPhrases() {
        #expect(HTTPStatus.ok.reasonPhrase == "OK")
        #expect(HTTPStatus.notFound.reasonPhrase == "Not Found")
        #expect(HTTPStatus.contentTooLarge.reasonPhrase == "Content Too Large")
        #expect(HTTPStatus.serviceUnavailable.reasonPhrase == "Service Unavailable")
        #expect(HTTPStatus(code: 425)?.reasonPhrase == "Too Early")  // RFC 8470 §5.2
        #expect(HTTPStatus(code: 599)?.reasonPhrase == nil)  // unregistered
    }

    @Test("every registered constant carries a reason-phrase")
    func registeredConstantsHavePhrases() {
        // The advisory text exists for the whole registered surface, so a downstream never re-types
        // the registry (RFC 9110 §15).
        let constants: [HTTPStatus] = [
            .continue, .switchingProtocols, .ok, .created, .accepted, .noContent, .partialContent,
            .movedPermanently, .found, .notModified, .badRequest, .unauthorized, .forbidden,
            .notFound, .methodNotAllowed, .preconditionFailed, .rangeNotSatisfiable,
            .requestTimeout, .contentTooLarge, .uriTooLong, .expectationFailed, .upgradeRequired,
            .tooManyRequests, .requestHeaderFieldsTooLarge, .internalServerError, .notImplemented,
            .badGateway, .serviceUnavailable, .gatewayTimeout, .httpVersionNotSupported
        ]
        let allNamed = constants.allSatisfy { $0.reasonPhrase != nil }
        #expect(allNamed)
    }

    @Test("accepts the boundary codes 100 and 599")
    func acceptsBoundaries() {
        #expect(HTTPStatus(code: 100)?.code == 100)
        #expect(HTTPStatus(code: 599)?.code == 599)
    }
}
