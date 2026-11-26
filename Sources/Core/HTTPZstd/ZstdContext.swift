//
//  ZstdContext.swift
//  HTTPZstd
//
//  Owns one libzstd context (compression or decompression): frees it exactly once, resets it between frames, and
//  hands its pointer to each C call. Only plain values are stored — the address as an integer and the kind of
//  context — so no class stores an unsafe type (SE-0458); the C functions are chosen at each call.
//

internal import CHTTPZstd

/// One owned libzstd context.
///
/// Used by one owner at a time — ``ZstdContextPool`` hands its owner out and takes it back — which is why it can be
/// `@unchecked Sendable`: it is moved between tasks, never shared.
final class ZstdContext: @unchecked Sendable {
    /// Which libzstd context this is.
    enum Kind {
        case compression
        case decompression
    }

    private let address: UInt
    private let kind: Kind

    /// Takes ownership of `pointer`, a context of `kind`, freed when this object goes away.
    private init(_ pointer: OpaquePointer, kind: Kind) {
        address = UInt(bitPattern: Int(bitPattern: pointer))
        self.kind = kind
    }

    /// A compression context at `level` that writes no content size into its frames.
    static func compression(level: Int) throws(ZstdError) -> ZstdContext {
        guard let pointer = unsafe chttpzstd_cctx_create(Int32(level)) else { throw .outOfMemory }
        return unsafe ZstdContext(pointer, kind: .compression)
    }

    /// A decompression context refusing windows over `1 << windowLogMax`.
    static func decompression(windowLogMax: Int) throws(ZstdError) -> ZstdContext {
        guard let pointer = unsafe chttpzstd_dctx_create(UInt32(windowLogMax)) else {
            throw .outOfMemory
        }
        return unsafe ZstdContext(pointer, kind: .decompression)
    }

    deinit {
        switch kind {
            case .compression:
                unsafe chttpzstd_cctx_free(pointer)
            case .decompression:
                unsafe chttpzstd_dctx_free(pointer)
        }
    }

    /// The context, for a C call.
    var pointer: OpaquePointer? {
        unsafe OpaquePointer(bitPattern: address)
    }

    /// Abandons any frame in progress; the next call starts a new frame.
    func reset() {
        switch kind {
            case .compression:
                _ = unsafe chttpzstd_cctx_reset(pointer)
            case .decompression:
                _ = unsafe chttpzstd_dctx_reset(pointer)
        }
    }
}
