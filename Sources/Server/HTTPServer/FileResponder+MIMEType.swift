//
//  FileResponder+MIMEType.swift
//  HTTPServer
//
//  Maps a filename extension to a media type for `Content-Type` (RFC 9110 §8.3). On Apple platforms this
//  is the system Uniform Type registry (``UTType``), which knows thousands of types; Linux has no
//  `UniformTypeIdentifiers`, so there it is a built-in table of the common web media types a static-file
//  server actually emits (anything absent falls back to `application/octet-stream`).
//

#if canImport(UniformTypeIdentifiers)
    internal import UniformTypeIdentifiers
#endif

extension FileResponder {
    /// The IANA media type for `ext` (lowercased, no leading dot), or nil if unknown.
    static func mimeType(forExtension ext: String) -> String? {
        #if canImport(UniformTypeIdentifiers)
            return UTType(filenameExtension: ext)?.preferredMIMEType
        #else
            return commonMIMETypes[ext]
        #endif
    }

    #if !canImport(UniformTypeIdentifiers)
        /// The common web media types by lowercased extension — the Linux fallback for the Apple-only
        /// ``UTType`` registry.
        ///
        /// Deliberately small: it covers what a static-file server serves, and the `text/*` entries gain
        /// `charset=utf-8` in ``contentType(_:)``.
        private static let commonMIMETypes: [String: String] = [
            "html": "text/html", "htm": "text/html", "xhtml": "application/xhtml+xml",
            "css": "text/css", "js": "text/javascript", "mjs": "text/javascript",
            "json": "application/json", "map": "application/json", "xml": "application/xml",
            "txt": "text/plain", "md": "text/markdown", "csv": "text/csv",
            "svg": "image/svg+xml", "png": "image/png", "jpg": "image/jpeg",
            "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp",
            "avif": "image/avif", "bmp": "image/bmp", "ico": "image/vnd.microsoft.icon",
            "woff": "font/woff", "woff2": "font/woff2", "ttf": "font/ttf",
            "otf": "font/otf", "eot": "application/vnd.ms-fontobject", "pdf": "application/pdf",
            "wasm": "application/wasm", "zip": "application/zip", "gz": "application/gzip",
            "mp4": "video/mp4", "webm": "video/webm", "mp3": "audio/mpeg",
            "ogg": "audio/ogg", "wav": "audio/wav", "weba": "audio/webm"
        ]
    #endif
}
