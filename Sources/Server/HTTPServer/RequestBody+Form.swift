//
//  RequestBody+Form.swift
//  HTTPServer
//
//  Phase 2.2 — decoding a request body as an HTML form: `application/x-www-form-urlencoded` (the same
//  encoding as the query component) or `multipart/form-data` (RFC 7578, with file parts). Convenience
//  over ``RequestBody`` that collects the body and parses it with the zero-dependency ``QueryParameters``
//  / ``MultipartFormData`` parsers in HTTPCore.
//

public import HTTPCore

extension RequestBody {
    /// Decodes an `application/x-www-form-urlencoded` body into form fields (RFC 1866 §8.2.1).
    ///
    /// Collects the body — prefer it for the small posted forms this content type carries; the fields
    /// read like the query (`form["email"]`, `form.email`).
    public func urlEncodedForm() async -> QueryParameters {
        QueryParameters.parse(form: String(decoding: await collect(), as: Unicode.UTF8.self))
    }

    /// Decodes a `multipart/form-data` body (RFC 7578) using the boundary from the request's Content-Type.
    ///
    /// Returns `nil` when `request` is not `multipart/form-data`, or when its body is malformed; collects
    /// the whole body, so pair it with a per-route limit (``Route/bodyLimited(to:)``) for file uploads.
    public func multipartForm(for request: HTTPRequest) async -> MultipartFormData? {
        guard let contentType = request.headerFields[.contentType],
            let boundary = MultipartFormData.boundary(ofContentType: contentType)
        else {
            return nil
        }
        return MultipartFormData.parse(await collect(), boundary: boundary)
    }
}
