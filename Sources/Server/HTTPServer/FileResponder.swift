//
//  FileResponder.swift
//  HTTPServer
//
//  Static file serving (RFC 9110). An ``HTTPResponder`` that maps a request path to a file under a root
//  directory and serves it with a content type (via the system `UTType` registry), `Last-Modified` /
//  `ETag` validators (from the file's mtime + size), conditional-request short-circuiting (`If-None-Match`
//  / `If-Modified-Since` → 304), and byte ranges (`206` / `416`, reusing the ``RangeMiddleware`` parser).
//  Path resolution is traversal-safe (CWE-22 / CWE-59): a `..`/`.` component is rejected and the
//  symlink-resolved path must stay under the root (a symlink under the root cannot escape). A file larger
//  than `streamingThreshold` is streamed in chunks (P6) rather than
//  buffered. Production niceties (G5): precompressed `.br`/`.gz` sidecars (``serveFile`` →
//  ``FileResponder+Precompressed``), an opt-in directory autoindex (``FileResponder+Autoindex``), and a
//  `try_files`-style SPA fallback for a missing path.
//

internal import Foundation
public import HTTPCore

/// Serves static files from a root directory — traversal-safe, with validators, conditionals, and ranges.
public struct FileResponder: HTTPResponder {
    let root: String
    let streamingThreshold: Int
    let precompressed: Bool
    let autoindex: Bool
    let fallback: String?

    /// Serves files under `root`.
    ///
    /// A response body larger than `streamingThreshold` octets is streamed. `precompressed` serves a fresh
    /// `.br`/`.gz` sidecar when the client accepts it; `autoindex` renders a directory listing (off by
    /// default); `fallback` (e.g. `"index.html"`) is served for a missing path (SPA `try_files`).
    public init(
        root: String,
        streamingThreshold: Int = 1 << 20,
        precompressed: Bool = true,
        autoindex: Bool = false,
        fallback: String? = nil
    ) {
        self.root = root
        self.streamingThreshold = max(0, streamingThreshold)
        self.precompressed = precompressed
        self.autoindex = autoindex
        self.fallback = fallback
    }

    /// What a resolved path points at.
    enum Resolution {
        case file(size: Int, modified: Int)
        case directory
        case missing
    }

    /// A file became unreadable, or shorter than its advertised length, between ``classify(_:)`` and the
    /// read — surfaced so the response fails closed (`500` / stream error) instead of under-delivering the
    /// `Content-Length` already on the wire (audit F1).
    private enum ReadError: Error {
        case unreadable
        case truncated
    }

    /// Resolves the request path to a file under the root and serves it, or `403`/`404`/`405`.
    public func respond(
        to request: HTTPRequest,
        body _: RequestBody,
        context _: RequestContext
    ) async -> ServerResponse {
        guard request.method == .get || request.method == .head else {
            var head = HTTPResponse(status: .methodNotAllowed)
            _ = head.headerFields.setValue("GET, HEAD", for: .allow)
            return ServerResponse(head)
        }
        // A traversal or otherwise malformed path is refused (CWE-22).
        guard let path = resolvedPath(request.path) else {
            return ServerResponse(HTTPResponse(status: .forbidden))
        }
        switch Self.classify(path) {
            case .file:
                return serveFile(path, request: request)
            case .directory:
                return serveDirectory(path, request: request)
            case .missing:
                return serveMissing(request: request)
        }
    }

    /// Serves a directory's `index.html`, an autoindex listing (when enabled), else `404`.
    private func serveDirectory(_ path: String, request: HTTPRequest) -> ServerResponse {
        let index = path + "/index.html"
        if case .file = Self.classify(index) {
            return serveFile(index, request: request)
        }
        guard autoindex else {
            return ServerResponse(HTTPResponse(status: .notFound))
        }
        return autoindexResponse(path, requestPath: request.path, omitBody: request.method == .head)
    }

    /// Serves the `fallback` file for a missing path (SPA `try_files`), else `404`.
    private func serveMissing(request: HTTPRequest) -> ServerResponse {
        guard let fallback, let path = resolvedPath("/" + fallback),
            case .file = Self.classify(path)
        else {
            return ServerResponse(HTTPResponse(status: .notFound))
        }
        return serveFile(path, request: request)
    }

    /// Serves a regular file: negotiates a precompressed sidecar, applies conditionals, and emits the body.
    private func serveFile(_ path: String, request: HTTPRequest) -> ServerResponse {
        let choice = precompressed ? precompressedChoice(path, request: request) : nil
        let servePath = choice?.path ?? path
        guard case .file(let size, let modified) = Self.classify(servePath) else {
            return ServerResponse(HTTPResponse(status: .notFound))
        }
        let etag = Self.entityTag(size: size, modified: modified, encoding: choice?.encoding)
        let lastModified = HTTPDate.imfFixdate(modified)
        if Self.isNotModified(request, etag: etag, modified: modified) {
            var head = HTTPResponse(status: .notModified)
            _ = head.headerFields.setValue(etag, for: .etag)
            _ = head.headerFields.setValue(lastModified, for: .lastModified)
            return ServerResponse(head)
        }
        var head = HTTPResponse(status: .ok)
        // The content type is the identity file's, never the `.br`/`.gz` sibling's.
        _ = head.headerFields.setValue(Self.contentType(path), for: .contentType)
        _ = head.headerFields.setValue(etag, for: .etag)
        _ = head.headerFields.setValue(lastModified, for: .lastModified)
        _ = head.headerFields.setValue("bytes", for: .acceptRanges)
        if let encoding = choice?.encoding {
            _ = head.headerFields.setValue(encoding, for: .contentEncoding)
            _ = head.headerFields.append("Accept-Encoding", for: .vary)
        }
        return serve(
            servePath,
            size: size,
            head: head,
            range: choice == nil ? request.headerFields[.range] : nil,  // ranges over identity only
            omitBody: request.method == .head
        )
    }

    /// Builds the response for a resolved file: a `206` for a satisfiable range, `416` for one past the
    /// end, else the full `200`; the body is buffered when small and streamed when large.
    private func serve(
        _ path: String,
        size: Int,
        head: HTTPResponse,
        range: String?,
        omitBody: Bool
    ) -> ServerResponse {
        var head = head
        var low = 0
        var high = size - 1
        if let range, size > 0 {
            switch RangeMiddleware.parse(range, total: size) {
                case .satisfiable(let start, let end):
                    low = start
                    high = end
                    head.status = .partialContent
                    _ = head.headerFields.setValue(
                        "bytes \(start)-\(end)/\(size)", for: .contentRange
                    )
                case .unsatisfiable:
                    var rejected = HTTPResponse(status: .rangeNotSatisfiable)
                    _ = rejected.headerFields.setValue("bytes */\(size)", for: .contentRange)
                    _ = rejected.headerFields.setValue("bytes", for: .acceptRanges)
                    return ServerResponse(rejected)
                case .ignore:
                    break  // serve the full representation (RFC 9110 §14.2)
            }
        }
        let length = size == 0 ? 0 : (high - low + 1)
        _ = head.headerFields.setValue(String(length), for: .contentLength)
        guard !omitBody else {
            return ServerResponse(head)  // HEAD: the header section only (RFC 9112 §6.3)
        }
        guard length > streamingThreshold else {
            guard let body = Self.readRange(path, offset: low, length: length) else {
                // The file went unreadable/short between classify and read — fail closed rather than emit
                // a body that contradicts the Content-Length already set above (audit F1).
                return ServerResponse(HTTPResponse(status: .internalServerError))
            }
            return ServerResponse(head, body: body)
        }
        let offset = low  // an immutable copy the @Sendable producer can capture
        let stream = ResponseStream(contentLength: length) { writer in
            try await Self.streamRange(path, offset: offset, length: length, to: writer)
        }
        return ServerResponse(head, stream: stream)
    }

    /// Resolves `target` to an absolute path under the root, or nil for a traversal / malformed path.
    func resolvedPath(_ target: String) -> String? {
        let pathPart = String(target.prefix { $0 != "?" && $0 != "#" })
        guard let decoded = pathPart.removingPercentEncoding else {
            return nil
        }
        let components = decoded.split(separator: "/").map(String.init)
        // Reject any traversal / current-dir component or an embedded NUL (CWE-22).
        guard !components.contains(where: { $0 == ".." || $0 == "." || $0.contains("\0") }) else {
            return nil
        }
        return inRoot(root + "/" + components.joined(separator: "/"))
    }

    /// The real (symlink-resolved) form of `absolutePath` if it stays inside the root, else nil.
    ///
    /// Resolves symlinks before the containment check (CWE-22): rejecting `..`/`.` components is not
    /// enough, because a symlink *inside* the root that points outside it (e.g. `root/link -> /etc`) has
    /// no `..` yet escapes — lexical standardization does not follow links. The root is resolved too so
    /// both sides are canonical (`resolvingSymlinksInPath` also standardizes away `.`/`..`).
    func inRoot(_ absolutePath: String) -> String? {
        let resolved = URL(fileURLWithPath: absolutePath).resolvingSymlinksInPath().path
        let rootResolved = URL(fileURLWithPath: root).resolvingSymlinksInPath().path
        guard resolved == rootResolved || resolved.hasPrefix(rootResolved + "/") else {
            return nil
        }
        return resolved
    }

    /// Classifies `path`: a regular file (with size + mtime), a directory, or missing.
    static func classify(_ path: String) -> Resolution {
        let manager = FileManager.default
        var isDirectory: ObjCBool = false
        guard manager.fileExists(atPath: path, isDirectory: &isDirectory) else {
            return .missing
        }
        if isDirectory.boolValue {
            return .directory
        }
        guard let attributes = try? manager.attributesOfItem(atPath: path),
            let size = attributes[.size] as? Int,
            let modified = attributes[.modificationDate] as? Date
        else {
            return .missing
        }
        return .file(size: size, modified: Int(modified.timeIntervalSince1970))
    }

    /// A strong entity-tag from the file's size and mtime (and content coding, when precompressed):
    /// `"<hex size>-<hex mtime>[-<coding>]"` (RFC 9110 §8.8.3).
    static func entityTag(size: Int, modified: Int, encoding: String?) -> String {
        let base = "\(String(size, radix: 16))-\(String(modified, radix: 16))"
        guard let encoding else {
            return "\"\(base)\""
        }
        return "\"\(base)-\(encoding)\""
    }

    /// Whether `If-None-Match` matches (weak) or `If-Modified-Since` is unmet — a `304` (RFC 9110 §13).
    private static func isNotModified(
        _ request: HTTPRequest,
        etag: String,
        modified: Int
    ) -> Bool {
        let ifNoneMatch = request.headerFields.values(for: .ifNoneMatch)
        if !ifNoneMatch.isEmpty {
            return matchesETag(ifNoneMatch, etag)
        }
        guard let ifModifiedSince = request.headerFields[.ifModifiedSince].flatMap(HTTPDate.parse)
        else {
            return false
        }
        return modified <= ifModifiedSince
    }

    /// Whether any `If-None-Match` entry matches `etag` under weak comparison (RFC 9110 §13.1.2).
    private static func matchesETag(_ ifNoneMatch: [String], _ etag: String) -> Bool {
        let target = opaque(etag)
        for value in ifNoneMatch {
            for element in value.split(separator: ",") {
                let candidate = element.trimmingCharacters(in: .whitespaces)
                if candidate == "*" || opaque(candidate) == target {
                    return true
                }
            }
        }
        return false
    }

    /// An entity-tag's value with any weak `W/` prefix removed (RFC 9110 §8.8.3).
    private static func opaque(_ tag: some StringProtocol) -> String {
        tag.hasPrefix("W/") ? String(tag.dropFirst(2)) : String(tag)
    }

    /// The content type for `path` by filename extension (``mimeType(forExtension:)`` — the system
    /// `UTType` registry on Apple, a built-in table on Linux), defaulting to `application/octet-stream`;
    /// a `text/*` type gains an explicit `charset=utf-8`.
    static func contentType(_ path: String) -> String {
        let ext = URL(fileURLWithPath: path).pathExtension.lowercased()
        guard !ext.isEmpty, let mime = mimeType(forExtension: ext) else {
            return "application/octet-stream"
        }
        return mime.hasPrefix("text/") ? "\(mime); charset=utf-8" : mime
    }

    /// Reads exactly `length` octets at `offset` from `path` (the small-file path).
    ///
    /// Returns `nil` if the file cannot deliver that many — so the caller fails closed instead of
    /// shipping a short body under a declared `Content-Length` (audit F1). An empty range
    /// (`length == 0`) is the valid empty body.
    private static func readRange(_ path: String, offset: Int, length: Int) -> [UInt8]? {
        guard length > 0 else {
            return []
        }
        guard let handle = FileHandle(forReadingAtPath: path) else {
            return nil
        }
        defer { try? handle.close() }
        do {
            try handle.seek(toOffset: UInt64(offset))
            guard let data = try handle.read(upToCount: length), data.count == length else {
                return nil  // open/seek succeeded but the file is now shorter than promised
            }
            return [UInt8](data)
        }
        catch {
            return nil
        }
    }

    /// Streams `length` octets at `offset` from `path` to `writer` in chunks (the large-file path).
    private static func streamRange(
        _ path: String,
        offset: Int,
        length: Int,
        to writer: any ResponseBodyWriter
    ) async throws {
        guard length > 0 else {
            return
        }
        guard let handle = FileHandle(forReadingAtPath: path) else {
            // The header section (incl. Content-Length) is already committed — fail the stream rather than
            // under-deliver and desync the connection (audit F1).
            throw ReadError.unreadable
        }
        defer { try? handle.close() }
        try handle.seek(toOffset: UInt64(offset))
        var remaining = length
        while remaining > 0 {
            guard let data = try handle.read(upToCount: min(64 * 1_024, remaining)), !data.isEmpty
            else {
                // EOF before the advertised length — never stop silently short.
                throw ReadError.truncated
            }
            try await writer.write([UInt8](data))
            remaining -= data.count
        }
    }
}
