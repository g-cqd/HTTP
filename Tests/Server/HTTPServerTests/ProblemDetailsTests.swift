//
//  ProblemDetailsTests.swift
//  HTTPServerTests
//
//  RFC 9457 — problem+json: the ``ProblemDetails`` body shape (status, fields, nil-field omission), the
//  ``ServerResponse/problem(_:)`` renderers, and ``ThrowingResponder`` mapping a thrown ``HTTPError`` to
//  its problem response (and a non-`HTTPError` to a leak-free `500`).
//

import Foundation
import HTTPCore
import HTTPServer
import Testing

@Suite("RFC 9457 — problem+json")
struct ProblemDetailsTests {
    private func decode(_ response: ServerResponse) throws -> ProblemDetails {
        try JSONDecoder().decode(ProblemDetails.self, from: Data(response.body))
    }

    private func get() -> HTTPRequest {
        HTTPRequest(method: .get, scheme: "https", authority: "x", path: "/")
    }

    @Test("ServerResponse.problem renders application/problem+json with the status and fields")
    func problemResponseShape() throws {
        let response = ServerResponse.problem(
            status: .notFound, detail: "no such user", title: "Not Found"
        )
        #expect(response.head.status == .notFound)
        #expect(response.head.headerFields[.contentType] == "application/problem+json")
        let problem = try decode(response)
        #expect(problem.status == 404)
        #expect(problem.title == "Not Found")
        #expect(problem.detail == "no such user")
        #expect(problem.type == "about:blank")
    }

    @Test("a nil problem field is omitted from the JSON (RFC 9457 §3.1)")
    func omitsNilFields() {
        let response = ServerResponse.problem(status: .badRequest)
        let json = String(bytes: response.body, encoding: .utf8) ?? ""
        #expect(json.contains("\"status\":400"))
        #expect(!json.contains("detail"))
        #expect(!json.contains("instance"))
    }

    @Test("ServerResponse.problem(HTTPError) uses the error's status and problem fields")
    func fromHTTPError() throws {
        let error = HTTPError(
            .forbidden, detail: "insufficient scope", type: "https://errors.example/forbidden"
        )
        let response = ServerResponse.problem(error)
        #expect(response.head.status == .forbidden)
        let problem = try decode(response)
        #expect(problem.status == 403)
        #expect(problem.detail == "insufficient scope")
        #expect(problem.type == "https://errors.example/forbidden")
    }

    @Test("ThrowingResponder maps a thrown HTTPError to its problem response")
    func throwingMapsHTTPError() async throws {
        let responder = ThrowingResponder { _, _, _ in
            throw HTTPError(.preconditionFailed, detail: "already exists")
        }
        let response = await responder.respond(to: get(), body: [])
        #expect(response.head.status == .preconditionFailed)
        #expect(response.head.headerFields[.contentType] == "application/problem+json")
        #expect(try decode(response).detail == "already exists")
    }

    @Test("ThrowingResponder maps a non-HTTPError to a bare 500 that leaks no error detail")
    func throwingMapsGenericError() async {
        struct Boom: Error { let secret = "do not leak" }
        let responder = ThrowingResponder { _, _, _ in throw Boom() }
        let response = await responder.respond(to: get(), body: [])
        #expect(response.head.status == .internalServerError)
        let json = String(bytes: response.body, encoding: .utf8) ?? ""
        #expect(!json.contains("do not leak"))
        #expect(!json.contains("secret"))
    }

    @Test("ThrowingResponder returns the handler's response when it does not throw")
    func throwingPassesThrough() async {
        let responder = ThrowingResponder { _, _, _ in .text("ok") }
        let response = await responder.respond(to: get(), body: [])
        #expect(response.head.status == .ok)
        #expect(response.body == Array("ok".utf8))
    }
}
