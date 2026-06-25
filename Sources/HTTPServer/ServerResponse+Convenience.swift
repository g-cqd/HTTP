//
//  ServerResponse+Convenience.swift
//  HTTPServer
//
//  Ergonomic constructors for the common response shapes — text, JSON, and a bodiless status — so a
//  route handler reads `.text("hi")` / `.json(bytes)` instead of hand-building ``HTTPFields`` each time.
//

public import HTTPCore

extension ServerResponse {
    /// A `text/plain; charset=utf-8` response (RFC 9110 §8.3).
    public static func text(_ body: String, status: HTTPStatus = .ok) -> ServerResponse {
        make(status, contentType: "text/plain; charset=utf-8", body: Array(body.utf8))
    }

    /// An `application/json` response (RFC 9110 §8.3 / RFC 8259); `body` is already-encoded JSON.
    public static func json(_ body: [UInt8], status: HTTPStatus = .ok) -> ServerResponse {
        make(status, contentType: "application/json", body: body)
    }

    /// A bodiless response carrying just `status` (e.g. `204`, `404`).
    public static func status(_ status: HTTPStatus) -> ServerResponse {
        ServerResponse(HTTPResponse(status: status))
    }

    /// Builds a response with a single `Content-Type` field and a body.
    private static func make(
        _ status: HTTPStatus,
        contentType: String,
        body: [UInt8]
    ) -> ServerResponse {
        var fields = HTTPFields()
        _ = fields.setValue(contentType, for: .contentType)
        return ServerResponse(HTTPResponse(status: status, headerFields: fields), body: body)
    }
}
