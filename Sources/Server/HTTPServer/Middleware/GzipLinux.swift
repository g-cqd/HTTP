//
//  GzipLinux.swift
//  HTTPServer
//
//  RFC 1952 gzip content coding for the non-Apple (Linux) build, via the in-house HTTPDeflate codec
//  (system zlib left this path with the CZlibCoding shim). The counterpart to Gzip.swift, which
//  frames Darwin's raw-DEFLATE encoder by hand; compiled only where Apple's Compression framework
//  is absent (`#if !canImport(Compression)`; Gzip.swift is excluded from the Linux graph), with the
//  same `compress(_:)` shape so CompressionMiddleware dispatches uniformly across platforms.
//
//  The buffered coding only. The streamed one is ``GzipEncoderStream`` in
//  GzipEncoderStreamLinux.swift, over the same ``GzipDeflator`` and — deliberately — the same
//  ``level``.
//

#if !canImport(Compression)

    internal import HTTPDeflate

    /// Produces gzip members (RFC 1952) via HTTPDeflate's one-shot encoder.
    enum Gzip {
        /// The DEFLATE effort grade both gzip paths encode at.
        ///
        /// Internal rather than private, and read by ``GzipEncoderStream`` rather than repeated
        /// there: the streamed and buffered codings of one representation must be byte-identical
        /// (see ``ContentEncoderStream``), and the level is one of the inputs that decides the
        /// output. Sharing the constant is what keeps a change to it from silently splitting the
        /// two.
        static let level = DeflateLevel.balanced

        /// Compresses `input` into a gzip member, or `nil` if it is empty (nothing to encode).
        static func compress(_ input: [UInt8]) -> [UInt8]? {
            guard !input.isEmpty else {
                return nil
            }
            return DeflateCodec.gzip(input, level: level)
        }
    }

#endif
