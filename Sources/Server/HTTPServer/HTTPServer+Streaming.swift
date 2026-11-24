//
//  HTTPServer+Streaming.swift
//  HTTPServer
//
//  Response-body streaming over HTTP/1.1 (``sendStreamedResponse(_:stream:omitBody:on:)``): the head goes
//  out with chunked transfer-coding (RFC 9112 §7.1), or a fixed Content-Length when the producer declared
//  one, then each chunk is written as it is produced. This file assumes HTTP/1.1 framing (chunked is not
//  valid for an HTTP/1.0 peer).
//
//  HTTP/2 and HTTP/3 stream natively on their own paths — `HTTPServer+HTTP2Streaming.swift` (RFC 9113
//  §8.1, over the engine's incremental DATA API) and `streamHTTP3Response` in `HTTPServer+HTTP3.swift`
//  (straight to the QUIC stream). Server-Sent Events therefore works on all three versions.
//

internal import HTTP1
internal import HTTPCore
internal import HTTPTransport

private enum ChunkedFramingBytes {
    static let crlf: [UInt8] = [0x0D, 0x0A]
    static let hexDigits: [UInt8] = Array("0123456789abcdef".utf8)
}

extension HTTPServer {
    /// Streams a response over HTTP/1.1.
    ///
    /// The head goes out chunked (or with Content-Length when the producer declared one), then each body
    /// chunk as it is produced; a chunked stream is terminated. Returns false on a transport fault.
    ///
    /// Every write is bounded by the idle deadline (FIX #1): the head send, each chunk send, and the
    /// terminator each (re-)arm `deadline` to `now + idleTimeout`, so a legit slow-but-**progressing**
    /// transfer is never reaped — each chunk resets the deadline — while a stalled chunk send (a
    /// slow-reading peer that has filled the socket send buffer) or a wedged inline producer (no chunk
    /// for a full window) IS reaped: the watchdog cancels this serve child task, unblocking the parked
    /// send through the transport's per-call cancellation. `deadline` is disarmed on every exit so the
    /// next exchange's read is not timed against a stale target.
    func sendStreamedResponse(
        _ head: HTTPResponse,
        stream: ResponseStream,
        omitBody: Bool,
        on connection: any TransportConnection,
        deadline: IdleDeadline
    ) async -> Bool {
        var head = head
        let chunked = stream.contentLength == nil
        if let length = stream.contentLength {
            _ = head.headerFields.setValue(String(length), for: .contentLength)
        }
        else {
            _ = head.headerFields.setValue("chunked", for: .transferEncoding)
        }
        defer { deadline.disarm() }
        do {
            deadline.arm(deadlineKey(after: limits.idleTimeout))
            try await connection.send(ResponseSerializer.serialize(head, body: [], omitBody: false))
            guard !omitBody else {
                return true  // HEAD: the header section only (RFC 9112 §6.3)
            }
            // The writer re-arms the deadline before each chunk send using the stream's producer
            // timeout when provided (issue #4), keeping socket sends bounded while allowing quiet
            // event-driven push producers (SSE, screen capture) to stay open without raising global
            // `HTTPLimits.idleTimeout`.
            let streamTimeout = stream.producerIdleTimeout ?? limits.idleTimeout
            deadline.arm(deadlineKey(after: streamTimeout))
            try await stream.produce(
                H1StreamWriter(
                    connection: connection,
                    chunked: chunked,
                    deadline: deadline,
                    clock: clock,
                    epoch: epoch,
                    writeTimeout: limits.idleTimeout,
                    producerTimeout: streamTimeout
                )
            )
            if chunked {
                deadline.arm(deadlineKey(after: limits.idleTimeout))
                try await connection.send(Array("0\r\n\r\n".utf8))  // last-chunk (RFC 9112 §7.1)
            }
            return true
        }
        catch {
            return false
        }
    }

    /// Writes HTTP/1.1 body chunks: chunked transfer-coding (RFC 9112 §7.1), or raw when length is known.
    private struct H1StreamWriter: ResponseBodyWriter {
        let connection: any TransportConnection
        let chunked: Bool
        /// The per-connection idle deadline, re-armed before each chunk send so progress resets it.
        ///
        /// FIX #1. Shared with the serve loop + its watchdog.
        let deadline: IdleDeadline
        let clock: C
        /// The instant ``DeadlineWheel`` keys are measured from — see `HTTPServer+DeadlineClock.swift`.
        let epoch: C.Instant
        let writeTimeout: Duration
        let producerTimeout: Duration

        func write(_ chunk: [UInt8]) async throws {
            guard !chunk.isEmpty else {
                return
            }
            // Bound the active socket send by `writeTimeout` (reaps stalled peers promptly), then
            // re-arm with `producerTimeout` for the gap until the next produced chunk (issue #4).
            deadline.arm(epoch.duration(to: clock.now) + writeTimeout)
            if chunked {
                // Scatter-gather send (`<hex>\r\n`, `chunk`, `\r\n`): avoids formatting via String
                // and avoids copying `chunk` into a temporary combined buffer (issue #2).
                let head = Self.chunkSizeLine(chunk.count)
                try await connection.send(head, chunk, ChunkedFramingBytes.crlf)
            }
            else {
                try await connection.send(chunk)
            }
            deadline.arm(epoch.duration(to: clock.now) + producerTimeout)
        }

        /// Formats `count` as lowercase ASCII hex followed by CRLF without going through `String`.
        private static func chunkSizeLine(_ count: Int) -> [UInt8] {
            var value = UInt(count)
            var digits: [UInt8] = []
            digits.reserveCapacity(18)
            repeat {
                digits.append(ChunkedFramingBytes.hexDigits[Int(value & 0xF)])
                value >>= 4
            } while value != 0
            digits.reverse()
            digits.append(0x0D)
            digits.append(0x0A)
            return digits
        }

        /// Hands an unframed file region to the transport's `sendfile(2)` path (G5).
        ///
        /// Only the raw (known `Content-Length`) body qualifies: its octets go on the wire unframed,
        /// so the kernel can copy file pages straight to the socket. A chunked body interleaves
        /// size-line framing per chunk (RFC 9112 §7.1), so it keeps the copying chunk pump — as do
        /// the backbones without a raw socket (the ``TransportConnection`` default).
        ///
        /// There is no open and no close here: the region already carries the descriptor the responder
        /// verified, and owns it for the whole response. Re-opening by pathname was the last place the
        /// bytes sent could differ from the bytes measured for the `Content-Length` (CWE-367).
        /// ``TransportConnection/sendFile(descriptor:offset:length:)`` documents that it does not close
        /// the caller's descriptor.
        func writeFile(_ region: FileRegion) async throws {
            guard !chunked, region.length > 0 else {
                try await FileRegionStreamer.stream(region, to: self)
                return
            }
            try await connection.sendFile(
                descriptor: region.descriptor, offset: region.offset, length: region.length
            )
        }
    }
}
