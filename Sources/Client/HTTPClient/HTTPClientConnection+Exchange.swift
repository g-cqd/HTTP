//
//  HTTPClientConnection+Exchange.swift
//  HTTPClient
//
//  RFC 9112 §4 / §6 — one request/response exchange on a pooled connection: serialize, send, parse
//  the status line + header section (skipping 1xx interim responses, §15.2), then read the body by
//  its framing (Content-Length, chunked, close-delimited) under the configured size bound.
//

internal import HTTP1
internal import HTTPCore

extension HTTPClientConnection {
    /// The raw (still content-coded) response of one exchange.
    struct RawResponse: Sendable {
        let head: ResponseHead
        let body: [UInt8]
    }

    /// Sends `requestBytes` and reads the complete response to a `method` request.
    func exchange(
        _ requestBytes: [UInt8],
        method: HTTPMethod,
        limits: HTTPLimits
    ) async throws -> RawResponse {
        try await write(requestBytes)
        while true {
            let (head, headLength) = try await readHead(method: method, limits: limits)
            consume(headLength)
            if (100 ..< 200).contains(head.response.status.code) {
                continue  // RFC 9110 §15.2: interim responses precede the final one
            }
            let body = try await readBody(head.framing, limits: limits)
            if !Self.keepsAlive(head) {
                isReusable = false
            }
            completedExchanges += 1
            return RawResponse(head: head, body: body)
        }
    }

    private func readHead(
        method: HTTPMethod, limits: HTTPLimits
    ) async throws -> (ResponseHead, Int) {
        let ceiling = limits.maxRequestLineLength + limits.maxHeaderListSize + 4
        while true {
            if let parsed = try Self.parseHead(plaintext, method: method, limits: limits) {
                return parsed
            }
            guard plaintext.count <= ceiling else {
                isReusable = false
                throw HTTPClientError.malformedResponse("response head exceeds \(ceiling) octets")
            }
            guard try await readMore() else {
                throw HTTPClientError.connectionClosed
            }
        }
    }

    private static func parseHead(
        _ bytes: [UInt8],
        method: HTTPMethod,
        limits: HTTPLimits
    ) throws -> (ResponseHead, Int)? {
        guard !bytes.isEmpty else {
            return nil
        }
        let result: Result<(ResponseHead, Int), HTTP1ParseError> = bytes.withUnsafeBytes { raw in
            Result { () throws(HTTP1ParseError) in
                // SAFETY: the reader is ~Escapable and confined to this borrow of `bytes`.
                var reader = unsafe ByteReader(raw)
                let head = try ResponseParser.parseHead(
                    &reader,
                    forRequestMethod: method,
                    limits: limits
                )
                return (head, reader.position)
            }
        }
        switch result {
            case .success(let parsed):
                return parsed
            case .failure(.incompleteHeaders):
                return nil
            case .failure(let error):
                throw HTTPClientError.malformedResponse("\(error)")
        }
    }

    private func readBody(
        _ framing: ResponseBodyFraming, limits: HTTPLimits
    ) async throws -> [UInt8] {
        switch framing {
            case .none:
                return []
            case .contentLength(let length):
                guard length <= limits.maxBodySize else {
                    isReusable = false
                    throw HTTPClientError.responseTooLarge(limit: limits.maxBodySize)
                }
                while plaintext.count < length {
                    guard try await readMore() else {
                        throw HTTPClientError.connectionClosed
                    }
                }
                let body = Array(plaintext[..<length])
                consume(length)
                return body
            case .chunked:
                return try await readChunked(limits: limits)
            case .untilEOF:
                while try await readMore() {
                    guard plaintext.count <= limits.maxBodySize else {
                        throw HTTPClientError.responseTooLarge(limit: limits.maxBodySize)
                    }
                }
                isReusable = false
                let body = plaintext
                consume(plaintext.count)
                return body
        }
    }

    private func readChunked(limits: HTTPLimits) async throws -> [UInt8] {
        var state = ChunkedBodyDecoder.State()
        var body: [UInt8] = []
        while true {
            let consumed = try Self.decodeChunks(
                plaintext,
                state: &state,
                into: &body,
                limits: limits
            )
            consume(consumed)
            if state.isComplete {
                return body
            }
            guard try await readMore() else {
                throw HTTPClientError.connectionClosed
            }
        }
    }

    private static func decodeChunks(
        _ bytes: [UInt8],
        state: inout ChunkedBodyDecoder.State,
        into body: inout [UInt8],
        limits: HTTPLimits
    ) throws -> Int {
        guard !bytes.isEmpty else {
            return 0
        }
        let result: Result<Int, HTTP1ParseError> = bytes.withUnsafeBytes { raw in
            Result { () throws(HTTP1ParseError) in
                // SAFETY: the reader is ~Escapable and confined to this borrow of `bytes`.
                var reader = unsafe ByteReader(raw)
                try ChunkedBodyDecoder.advance(&reader, state: &state, into: &body, limits: limits)
                return reader.position
            }
        }
        switch result {
            case .success(let consumed):
                return consumed
            case .failure(.bodyTooLarge):
                throw HTTPClientError.responseTooLarge(limit: limits.maxBodySize)
            case .failure(let error):
                throw HTTPClientError.malformedResponse("chunked body: \(error)")
        }
    }

    /// RFC 9112 §9.3: HTTP/1.1 persists unless `Connection: close`; HTTP/1.0 never does here.
    private static func keepsAlive(_ head: ResponseHead) -> Bool {
        guard head.version == .http11 else {
            return false
        }
        return !head.response.headerFields.values(for: .connection)
            .contains { value in
                ContentCodings.tokens(value).contains("close")
            }
    }
}
