//
//  MultipartFormData.swift
//  HTTPCore
//
//  RFC 7578 — `multipart/form-data` request bodies: a sequence of parts separated by a `--boundary`
//  delimiter (RFC 2046 §5.1), each a small header section (`Content-Disposition` naming the field, plus
//  an optional `Content-Type`) followed by its raw bytes. Parsing is lenient and trap-free: a malformed
//  body returns `nil` rather than crashing, so an attacker-controlled upload never traps the parser.
//  Zero-dependency (no Foundation); the boundary is read from the request's `Content-Type` (§4.1).
//

/// A parsed `multipart/form-data` body (RFC 7578): its form parts, in order.
public struct MultipartFormData: Sendable, Equatable {
    /// One form part: its field `name`, an optional `filename` (a file upload), an optional declared
    /// `Content-Type`, and its raw body bytes (RFC 7578 §4.2).
    public struct Part: Sendable, Equatable {
        /// The form field name (the `Content-Disposition` `name` parameter, RFC 7578 §4.2).
        public var name: String
        /// The uploaded file's name (the `filename` parameter), or `nil` for a non-file field.
        public var filename: String?
        /// The part's declared `Content-Type`, or `nil` if it carried none.
        public var contentType: String?
        /// The part's raw body bytes.
        public var body: [UInt8]

        /// Creates a form part.
        public init(
            name: String,
            filename: String? = nil,
            contentType: String? = nil,
            body: [UInt8]
        ) {
            self.name = name
            self.filename = filename
            self.contentType = contentType
            self.body = body
        }
    }

    /// The parts, in the order they appeared.
    public var parts: [Part]

    /// Creates a multipart body from `parts`.
    public init(parts: [Part]) {
        self.parts = parts
    }

    /// The first part named `name` (a form field may repeat; this returns the first), or `nil`.
    public subscript(_ name: String) -> Part? { parts.first { $0.name == name } }

    /// Every part named `name`, in order (for repeated fields such as multi-file inputs).
    public func all(_ name: String) -> [Part] { parts.filter { $0.name == name } }

    /// Parses a `multipart/form-data` body delimited by `boundary` (RFC 7578 §4 / RFC 2046 §5.1).
    ///
    /// Returns `nil` if `boundary` is outside the RFC 2046 §5.1.1 grammar, if the body has no valid
    /// opening or closing delimiter, or if it breaches `limits`; a part missing a
    /// `Content-Disposition` `name` is skipped. Lenient and trap-free — a malformed or hostile body
    /// returns `nil` rather than trapping.
    public static func parse(
        _ body: [UInt8],
        boundary: String,
        limits: MultipartLimits = .default
    ) -> Self? {
        guard let validated = MultipartBoundary(boundary) else {
            return nil
        }
        return body.withUnsafeBytes { raw in
            var parser = MultipartParser(body: raw.bytes, boundary: validated, limits: limits)
            return parser.parse()
        }
    }

    /// The `boundary` parameter of a `multipart/form-data` `Content-Type` value (RFC 7578 §4.1), or nil.
    ///
    /// Returns `nil` when the parameter is absent *or* when its value is outside the RFC 2046 §5.1.1
    /// `boundary` grammar, so a caller can never hand ``parse(_:boundary:)`` an unusable delimiter.
    public static func boundary(ofContentType value: String) -> String? {
        guard let candidate = parameter("boundary", in: value),
            MultipartBoundary(candidate) != nil
        else {
            return nil
        }
        return candidate
    }

    /// The value of the `name=` parameter in a header value (e.g. `form-data; name="x"`), unquoted; nil
    /// if absent.
    private static func parameter(_ name: String, in value: String) -> String? {
        MultipartParameters.value(of: name, in: value)
    }
}
