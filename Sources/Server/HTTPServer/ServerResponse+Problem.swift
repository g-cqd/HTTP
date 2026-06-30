//
//  ServerResponse+Problem.swift
//  HTTPServer
//
//  Renders an RFC 9457 ``ProblemDetails`` (or an ``HTTPError``) to an `application/problem+json`
//  response (RFC 9457 §3). The body is encoded with sorted keys so the output is deterministic; a
//  `nil` problem field is omitted (synthesized `encodeIfPresent`). The Content-Type is the registered
//  problem media type so a client can distinguish a structured error from an ordinary JSON body.
//

internal import Foundation
public import HTTPCore

extension ServerResponse {
    /// An `application/problem+json` response carrying `problem` (RFC 9457 §3).
    ///
    /// The status is `status` when given, else the problem's own `status` field, else `500`.
    public static func problem(
        _ problem: ProblemDetails,
        status: HTTPStatus? = nil
    ) -> ServerResponse {
        let code =
            status
            ?? problem.status.flatMap(HTTPStatus.init(code:))
            ?? .internalServerError
        var fields = HTTPFields()
        _ = fields.setValue("application/problem+json", for: .contentType)
        return ServerResponse(
            HTTPResponse(status: code, headerFields: fields), body: Self.encode(problem)
        )
    }

    /// An `application/problem+json` response for `error`, using its status and problem fields.
    public static func problem(_ error: HTTPError) -> ServerResponse {
        problem(error.problemDetails, status: error.status)
    }

    /// An `application/problem+json` response built from `status` and the given problem fields.
    public static func problem(
        status: HTTPStatus,
        detail: String? = nil,
        title: String? = nil,
        type: String = "about:blank"
    ) -> ServerResponse {
        problem(
            ProblemDetails(type: type, title: title, status: Int(status.code), detail: detail),
            status: status
        )
    }

    /// Encodes `problem` to deterministic JSON, falling back to a minimal `500` body on the (practically
    /// impossible) encode failure so an error response never itself fails to serialize.
    private static func encode(_ problem: ProblemDetails) -> [UInt8] {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(problem) else {
            return Array(#"{"status":500,"title":"Internal Server Error"}"#.utf8)
        }
        return [UInt8](data)
    }
}
