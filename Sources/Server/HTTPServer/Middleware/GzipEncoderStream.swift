//
//  GzipEncoderStream.swift
//  HTTPServer
//
//  The incremental `gzip` content coding (RFC 1952) — the streaming counterpart of ``Gzip/compress(_:)``.
//  Same envelope as the one-shot path, from the same constants, so the two produce identical members:
//  the 10-octet header, the DEFLATE stream, then CRC-32 and ISIZE.
//
//  The trailer is the whole reason this is not just a wrapper around ``CompressionFrameworkStream``.
//  The one-shot path checksums the payload after deflating it, which it can only do because it still
//  holds the payload; a streamed body is gone by then. Both trailer fields are therefore folded as the
//  octets go past — the CRC through ``CRC32/Running``, and ISIZE as a wrapping 32-bit count, which is
//  what RFC 1952 §2.3.1 specifies (the size modulo 2^32, not a saturating or rejected one).
//

#if canImport(Compression)

    internal import Compression
    internal import HTTPCore

    /// An incremental gzip member (RFC 1952): header, DEFLATE, CRC-32 + ISIZE trailer.
    final class GzipEncoderStream: ContentEncoderStream {
        private let deflate: CompressionFrameworkStream

        /// The CRC-32 of the *uncompressed* octets seen so far (RFC 1952 §2.3.1).
        private var checksum = CRC32.Running()

        /// The uncompressed length modulo 2^32 — the ISIZE field, wrapping is specified, not a defect.
        private var inputSize: UInt32 = 0

        /// Whether the header still has to go out; it rides the first output rather than being emitted
        /// at construction, so a stream that is created and then dropped writes nothing at all.
        private var headerPending = true

        /// Starts a gzip member, or nil when the framework will not encode DEFLATE.
        init?() {
            guard let deflate = CompressionFrameworkStream(COMPRESSION_ZLIB) else {
                return nil
            }
            self.deflate = deflate
        }

        deinit {
            // The codec state is the `CompressionFrameworkStream`'s to free; ARC releases it here.
        }

        func update(_ input: [UInt8]) throws(ContentEncodingError) -> [UInt8] {
            checksum.update(input)
            inputSize &+= UInt32(truncatingIfNeeded: input.count)
            var coded = takeHeader()
            coded.append(contentsOf: try deflate.process(input, finalize: false))
            return coded
        }

        func finish() throws(ContentEncodingError) -> [UInt8] {
            var coded = takeHeader()
            coded.append(contentsOf: try deflate.process([], finalize: true))
            Gzip.appendLittleEndian(checksum.checksum, to: &coded)
            Gzip.appendLittleEndian(inputSize, to: &coded)
            return coded
        }

        /// The header on the first call, nothing after.
        private func takeHeader() -> [UInt8] {
            guard headerPending else {
                return []
            }
            headerPending = false
            return Gzip.header
        }
    }

#endif
