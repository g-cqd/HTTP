//
//  FileResponder.swift
//  HTTPServer
//
//  Static file serving (RFC 9110). An ``HTTPResponder`` that maps a request path to a file under a root
//  directory and serves it with a content type (via the system `UTType` registry), `Last-Modified` /
//  `ETag` validators
//  (from the file's mtime + size), conditional-request short-circuiting (`If-None-Match` /
//  `If-Modified-Since` → 304), and byte ranges (`206` / `416`, reusing the ``RangeMiddleware`` parser).
//  Path resolution is traversal-safe (CWE-22): a `..`/`.` component is rejected and the resolved path
//  must stay under the root. A file larger than `streamingThreshold` is streamed in chunks (P6) rather
//  than buffered, so a large download never holds the whole file in memory.
//

internal import Foundation
public import HTTPCore
internal import UniformTypeIdentifiers

/// Serves static files from a root directory — traversal-safe, with validators, conditionals, and ranges.
public struct FileResponder: HTTPResponder {
    private let root: String
    private let streamingThreshold: Int

    /// Serves files under `root`; a response body larger than `streamingThreshold` octets is streamed.
    public init(root: String, streamingThreshold: Int = 1 << 20) {
        self.root = root
        self.streamingThreshold = max(0, streamingThreshold)
    }

    /// Resolves the request path to a file under the root and serves it, or `403`/`404`/`405`.
    public func respond(to request: HTTPRequest, body _: [UInt8]) async -> ServerResponse {
        guard request.method == .get || request.method == .head else {
            var head = HTTPResponse(status: .methodNotAllowed)
            _ = head.headerFields.setValue("GET, HEAD", for: .allow)
            return ServerResponse(head)
        }
        guard let path = resolvedPath(request.path) else {
            // A traversal or otherwise malformed path (CWE-22).
            return ServerResponse(HTTPResponse(status: .forbidden))
        }
        guard let info = Self.fileInfo(path) else {
            return ServerResponse(HTTPResponse(status: .notFound))
        }
        let etag = Self.entityTag(info)
        let lastModified = HTTPDate.imfFixdate(info.modified)
        if Self.isNotModified(request, etag: etag, modified: info.modified) {
            var head = HTTPResponse(status: .notModified)
            _ = head.headerFields.setValue(etag, for: .etag)
            _ = head.headerFields.setValue(lastModified, for: .lastModified)
            return ServerResponse(head)
        }
        var head = HTTPResponse(status: .ok)
        _ = head.headerFields.setValue(Self.contentType(path), for: .contentType)
        _ = head.headerFields.setValue(etag, for: .etag)
        _ = head.headerFields.setValue(lastModified, for: .lastModified)
        _ = head.headerFields.setValue("bytes", for: .acceptRanges)
        return serve(
            path,
            size: info.size,
            head: head,
            range: request.headerFields[.range],
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
            return ServerResponse(head, body: Self.readRange(path, offset: low, length: length))
        }
        let offset = low  // an immutable copy the @Sendable producer can capture
        let stream = ResponseStream(contentLength: length) { writer in
            try await Self.streamRange(path, offset: offset, length: length, to: writer)
        }
        return ServerResponse(head, stream: stream)
    }

    /// Resolves `target` to an absolute path under the root, or nil for a traversal / malformed path.
    private func resolvedPath(_ target: String) -> String? {
        let pathPart = String(target.prefix { $0 != "?" && $0 != "#" })
        guard let decoded = pathPart.removingPercentEncoding else {
            return nil
        }
        let components = decoded.split(separator: "/").map(String.init)
        // Reject any traversal / current-dir component or an embedded NUL (CWE-22).
        guard !components.contains(where: { $0 == ".." || $0 == "." || $0.contains("\0") }) else {
            return nil
        }
        let relative = components.isEmpty ? "index.html" : components.joined(separator: "/")
        let standardized = URL(fileURLWithPath: root + "/" + relative).standardizedFileURL.path
        let rootStandardized = URL(fileURLWithPath: root).standardizedFileURL.path
        guard standardized == rootStandardized || standardized.hasPrefix(rootStandardized + "/")
        else {
            return nil  // resolved outside the root — refuse (CWE-22)
        }
        return standardized
    }

    /// The size and modification time (epoch seconds) of a regular file, or nil if missing / a directory.
    private static func fileInfo(_ path: String) -> (size: Int, modified: Int)? {
        let manager = FileManager.default
        var isDirectory: ObjCBool = false
        guard manager.fileExists(atPath: path, isDirectory: &isDirectory), !isDirectory.boolValue,
            let attributes = try? manager.attributesOfItem(atPath: path),
            let size = attributes[.size] as? Int,
            let modified = attributes[.modificationDate] as? Date
        else {
            return nil
        }
        return (size, Int(modified.timeIntervalSince1970))
    }

    /// A strong entity-tag from the file's size and mtime: `"<hex size>-<hex mtime>"` (RFC 9110 §8.8.3).
    private static func entityTag(_ info: (size: Int, modified: Int)) -> String {
        "\"\(String(info.size, radix: 16))-\(String(info.modified, radix: 16))\""
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

    /// The content type for `path`, from the system Uniform Type registry (``UTType``), defaulting to
    /// `application/octet-stream`; a `text/*` type gains an explicit `charset=utf-8`.
    private static func contentType(_ path: String) -> String {
        let ext = URL(fileURLWithPath: path).pathExtension
        guard !ext.isEmpty, let mime = UTType(filenameExtension: ext)?.preferredMIMEType else {
            return "application/octet-stream"
        }
        return mime.hasPrefix("text/") ? "\(mime); charset=utf-8" : mime
    }

    /// Reads `length` octets at `offset` from `path` into a buffer (the small-file path).
    private static func readRange(_ path: String, offset: Int, length: Int) -> [UInt8] {
        guard length > 0, let handle = FileHandle(forReadingAtPath: path) else {
            return []
        }
        defer { try? handle.close() }
        try? handle.seek(toOffset: UInt64(offset))
        guard let data = try? handle.read(upToCount: length) else {
            return []
        }
        return [UInt8](data)
    }

    /// Streams `length` octets at `offset` from `path` to `writer` in chunks (the large-file path).
    private static func streamRange(
        _ path: String,
        offset: Int,
        length: Int,
        to writer: any ResponseBodyWriter
    ) async throws {
        guard length > 0, let handle = FileHandle(forReadingAtPath: path) else {
            return
        }
        defer { try? handle.close() }
        try handle.seek(toOffset: UInt64(offset))
        var remaining = length
        while remaining > 0 {
            guard let data = try handle.read(upToCount: min(64 * 1_024, remaining)), !data.isEmpty
            else {
                break
            }
            try await writer.write([UInt8](data))
            remaining -= data.count
        }
    }
}
