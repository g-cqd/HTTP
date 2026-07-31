//
//  FileResponder.swift
//  HTTPServer
//
//  Static file serving (RFC 9110). An ``HTTPResponder`` that maps a request path to a file under a root
//  directory and serves it with a content type (via the system `UTType` registry), `Last-Modified` /
//  `ETag` validators (``FileValidator`` — weak, from the descriptor's own `fstat(2)`),
//  conditional-request short-circuiting (`If-None-Match` / `If-Modified-Since` → 304), and byte ranges
//  (`206` / `416`, reusing the ``RangeMiddleware`` parser).
//
//  Path resolution is descriptor-anchored (``RootDirectory``): the root is opened once and every request
//  component is an `openat(2)` hop with `O_NOFOLLOW` from it, so containment is structural rather than a
//  string prefix and the descriptor that is verified is the very descriptor that is stat'd, read, and
//  handed to `sendfile(2)`. A `..`/`.`/NUL component is still rejected lexically first, as defense in
//  depth and as the source of the `403` (CWE-22 traversal, CWE-59 link following, CWE-367 TOCTOU).
//
//  A file larger than `streamingThreshold` is streamed in chunks (P6) rather than buffered. Production
//  niceties (G5): precompressed `.br`/`.gz` sidecars (``serveFile`` → ``FileResponder+Precompressed``),
//  an opt-in directory autoindex (``FileResponder+Autoindex``), and a `try_files`-style SPA fallback for
//  a missing path.
//

internal import Foundation
public import HTTPCore

/// Serves static files from a root directory — traversal-safe, with validators, conditionals, and ranges.
public struct FileResponder: HTTPResponder {
    /// The directory index filename served for a directory request.
    static let indexName: Substring = "index.html"

    /// The root directory descriptor every lookup is anchored on, or nil when `root` was not a directory.
    let root: RootDirectory?
    let streamingThreshold: Int
    let precompressed: Bool
    let autoindex: Bool
    let fallback: String?

    /// Serves files under `root`.
    ///
    /// `root` is opened once, here, and never resolved by name again — so moving or replacing the root
    /// path afterwards cannot redirect a lookup (CWE-367). A response body larger than
    /// `streamingThreshold` octets is streamed. `precompressed` serves a fresh `.br`/`.gz` sidecar when
    /// the client accepts it; `autoindex` renders a directory listing (off by default); `fallback` (e.g.
    /// `"index.html"`) is served for a missing path (SPA `try_files`).
    public init(
        root: String,
        streamingThreshold: Int = 1 << 20,
        precompressed: Bool = true,
        autoindex: Bool = false,
        fallback: String? = nil
    ) {
        self.root = RootDirectory(path: root)
        self.streamingThreshold = max(0, streamingThreshold)
        self.precompressed = precompressed
        self.autoindex = autoindex
        self.fallback = fallback
    }

    /// Resolves the request path to a file under the root and serves it, or `403`/`404`/`405`/`500`.
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
        // A root that is not a directory is a misconfiguration, not a missing resource.
        guard let root else {
            return ServerResponse(HTTPResponse(status: .internalServerError))
        }
        // A traversal or otherwise malformed path is refused before a single syscall (CWE-22).
        guard let components = Self.components(of: request.path) else {
            return ServerResponse(HTTPResponse(status: .forbidden))
        }
        switch root.resolve(components) {
            case .file(let file, let parent):
                return serveFile(file, named: components.last ?? "", in: parent, request: request)
            case .directory(let directory):
                return serveDirectory(directory, request: request)
            case .missing:
                return serveMissing(request: request)
            case .refused:
                return ServerResponse(HTTPResponse(status: .forbidden))
            case .unavailable:
                return ServerResponse(HTTPResponse(status: .internalServerError))
        }
    }

    /// Serves a directory's `index.html`, an autoindex listing (when enabled), else `404`.
    private func serveDirectory(
        _ directory: OpenedDirectory,
        request: HTTPRequest
    ) -> ServerResponse {
        if let index = directory.openFile(named: Self.indexName) {
            return serveFile(index, named: Self.indexName, in: directory, request: request)
        }
        guard autoindex else {
            return ServerResponse(HTTPResponse(status: .notFound))
        }
        return autoindexResponse(
            directory, requestPath: request.path, omitBody: request.method == .head
        )
    }

    /// Serves the `fallback` file for a missing path (SPA `try_files`), else `404`.
    private func serveMissing(request: HTTPRequest) -> ServerResponse {
        guard let root, let fallback,
            let components = Self.components(of: "/" + fallback),
            let name = components.last,
            case .file(let file, let parent) = root.resolve(components)
        else {
            return ServerResponse(HTTPResponse(status: .notFound))
        }
        return serveFile(file, named: name, in: parent, request: request)
    }

    /// Serves a regular file: negotiates a precompressed sidecar, applies conditionals, and emits the body.
    ///
    /// Every validator comes off the open descriptor's own `fstat`, so there is no second lookup to
    /// disagree with the first — the `Content-Length`, `ETag`, and `Last-Modified` on the wire always
    /// describe the bytes the body will carry (CWE-367).
    ///
    /// `Vary` is decided by the *resource*, not by what this one request happened to negotiate, and is
    /// therefore identical on the `200` and on the `304` that revalidates it (RFC 9110 §12.5.5,
    /// §15.4.5). A cache keyed on the 200's `Vary` and later handed a `Vary`-less `304` would be told
    /// the resource stopped being negotiated, and could replay stored Brotli bytes to a client that
    /// never asked for them.
    private func serveFile(
        _ file: OpenedFile,
        named name: Substring,
        in directory: OpenedDirectory,
        request: HTTPRequest
    ) -> ServerResponse {
        // Whether a sidecar *could* be offered for this resource — not whether one was, and not
        // whether this request would have taken it. Only that is invariant across statuses.
        let negotiated = precompressed && Self.isCompressible(name)
        // One parse of `Accept-Encoding` per request, shared by the sidecar choice and the identity
        // check below; a range is always served from the identity bytes, so no sidecar is sought.
        let accept = AcceptEncoding(request.headerFields[.acceptEncoding])
        let choice =
            negotiated && request.headerFields[.range] == nil
            ? precompressedChoice(file, named: name, in: directory, accept: accept) : nil
        // A client that excluded `identity` and cannot be given a coded representation has no
        // acceptable one at all (RFC 9110 §12.5.3, §15.5.7).
        guard choice != nil || accept.identityIsAcceptable else {
            return ServerResponse(HTTPResponse(status: .notAcceptable))
        }
        let served = choice?.file ?? file
        let etag = FileValidator.entityTag(for: served, encoding: choice?.encoding)
        let lastModified = HTTPDate.imfFixdate(served.modifiedAt)
        if Self.isNotModified(request, etag: etag, modified: served.modifiedAt) {
            var head = HTTPResponse(status: .notModified)
            _ = head.headerFields.setValue(etag, for: .etag)
            _ = head.headerFields.setValue(lastModified, for: .lastModified)
            // No `Content-Encoding`: §15.4.5 asks a 304 not to carry representation metadata beyond
            // what guides a cache update, and the coding is already folded into the `ETag`.
            if negotiated {
                _ = head.headerFields.append("Accept-Encoding", for: .vary)
            }
            return ServerResponse(head)
        }
        var head = HTTPResponse(status: .ok)
        // The content type is the identity file's, never the `.br`/`.gz` sibling's.
        _ = head.headerFields.setValue(Self.contentType(name), for: .contentType)
        _ = head.headerFields.setValue(etag, for: .etag)
        _ = head.headerFields.setValue(lastModified, for: .lastModified)
        _ = head.headerFields.setValue("bytes", for: .acceptRanges)
        if negotiated {
            _ = head.headerFields.append("Accept-Encoding", for: .vary)
        }
        if let encoding = choice?.encoding {
            _ = head.headerFields.setValue(encoding, for: .contentEncoding)
        }
        return serve(
            served,
            head: head,
            range: choice == nil ? request.headerFields[.range] : nil,  // ranges over identity only
            omitBody: request.method == .head
        )
    }

    /// Builds the response for a resolved file: a `206` for a satisfiable range, `416` for one past the
    /// end, else the full `200`; the body is buffered when small and streamed when large.
    private func serve(
        _ file: OpenedFile,
        head: HTTPResponse,
        range: String?,
        omitBody: Bool
    ) -> ServerResponse {
        var head = head
        let size = file.size
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
            guard let body = file.read(offset: low, length: length) else {
                // The file was truncated between the fstat and the read — fail closed rather than emit
                // a body that contradicts the Content-Length already set above (audit F1).
                return ServerResponse(HTTPResponse(status: .internalServerError))
            }
            return ServerResponse(head, body: body)
        }
        // The region holds the OpenedFile, so the verified descriptor outlives this call and stays open
        // for the whole stream — the h1 writer hands it to the transport's sendfile(2) (kernel copy, no
        // userspace round-trip); every other engine/framing streams it through the bounded copying pump.
        let region = FileRegion(file: file, offset: low, length: length)
        let stream = ResponseStream(contentLength: length) { writer in
            try await writer.writeFile(region)
        }
        return ServerResponse(head, stream: stream)
    }

    /// The path components of `target` under the root, or nil for a traversal / malformed path.
    ///
    /// The query and fragment are dropped, the path is percent-decoded, and any `..`/`.`/NUL component is
    /// rejected (CWE-22). Returns the components themselves rather than a joined path: they are what
    /// ``RootDirectory/resolve(_:)`` walks, one `openat(2)` hop each.
    static func components(of target: String) -> [Substring]? {
        let pathPart = String(target.prefix { $0 != "?" && $0 != "#" })
        guard let decoded = pathPart.removingPercentEncoding else {
            return nil
        }
        let components = decoded.split(separator: "/")
        guard !components.contains(where: { $0 == ".." || $0 == "." || $0.utf8.contains(0) }) else {
            return nil
        }
        return components
    }

    /// Whether `If-None-Match` matches (weak) or `If-Modified-Since` is unmet — a `304` (RFC 9110 §13).
    private static func isNotModified(
        _ request: HTTPRequest,
        etag: String,
        modified: Int
    ) -> Bool {
        let ifNoneMatch = request.headerFields.values(for: .ifNoneMatch)
        if !ifNoneMatch.isEmpty {
            return EntityTag.weakMatches(ifNoneMatch, etag)
        }
        guard let ifModifiedSince = request.headerFields[.ifModifiedSince].flatMap(HTTPDate.parse)
        else {
            return false
        }
        return modified <= ifModifiedSince
    }

    /// The content type for `name` by filename extension (``mimeType(forExtension:)`` — the system
    /// `UTType` registry on Apple, a built-in table on Linux), defaulting to `application/octet-stream`;
    /// a `text/*` type gains an explicit `charset=utf-8`.
    static func contentType(_ name: some StringProtocol) -> String {
        guard let dot = name.lastIndex(of: "."), dot != name.startIndex else {
            return "application/octet-stream"  // no extension, or a dotfile like `.gitignore`
        }
        let ext = name[name.index(after: dot)...].lowercased()
        guard !ext.isEmpty, let mime = mimeType(forExtension: ext) else {
            return "application/octet-stream"
        }
        return mime.hasPrefix("text/") ? "\(mime); charset=utf-8" : mime
    }
}
