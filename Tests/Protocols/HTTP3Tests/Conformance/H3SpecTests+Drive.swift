//
//  H3SpecTests+Drive.swift
//  HTTP3Tests
//
//  The per-row drive-and-assert harness for the live conformance pass. For each `.supported` catalog
//  row, `injections` maps its title to a malformation fed into a fresh ``HTTP3Connection``; `drive`
//  runs it and reports the QUIC application error code the engine answers with (from the queued
//  CONNECTION_CLOSE for a connection error, or RESET_STREAM for a stream error). `expectedWireCode`
//  parses the mandated code out of the catalog's `expect` string, and `isAcceptable` allows the
//  generic-error substitution the catalog's tolerance rule permits.
//

import HTTPCore

@testable import HTTP3

extension H3SpecTests {
    /// Runs the injection for `check` and returns the error code the engine answered with, or nil.
    func drive(_ check: H3Check) -> UInt64? {
        guard let injection = injections[check.title] else {
            return nil
        }
        return observedCode(injection)
    }

    /// Runs `body` against a fresh connection and returns the first close/reset error code it queued.
    private func observedCode(_ body: (inout HTTP3Connection) -> Void) -> UInt64? {
        var connection = HTTP3Connection()
        body(&connection)
        for action in connection.outbound() {
            if case .closeConnection(let code) = action {
                return code
            }
            if case .resetStream(_, let code) = action {
                return code
            }
        }
        return nil
    }

    /// Parses the `(0x….)` wire code out of a catalog `expect` string.
    func expectedWireCode(_ expect: String) -> UInt64? {
        guard let open = expect.firstIndex(of: "(") else {
            return nil
        }
        let after = expect.index(after: open)
        guard let close = expect[after...].firstIndex(of: ")") else {
            return nil
        }
        let inside = expect[after ..< close]
        guard inside.hasPrefix("0x") else {
            return nil
        }
        return UInt64(inside.dropFirst(2), radix: 16)
    }

    /// Whether `observed` satisfies `expected`, allowing the generic HTTP/3 error substitution the
    /// catalog tolerates (RFC 9114 §8 / RFC 9000 §11).
    func isAcceptable(_ observed: UInt64, expected: UInt64) -> Bool {
        observed == expected
            || observed == HTTP3ErrorCode.h3GeneralProtocolError.rawValue
            || observed == HTTP3ErrorCode.h3InternalError.rawValue
    }

    /// One malformation injection per `.supported` catalog row, keyed by the row's title.
    private var injections: [String: (inout HTTP3Connection) -> Void] {
        let request = QUICStreamID(0)
        let control = QUICStreamID(2)
        let encoder = QUICStreamID(6)
        let decoder = QUICStreamID(10)
        let secondUni = QUICStreamID(14)
        let pushStream = QUICStreamID(18)
        let base = [
            HeaderField(name: ":method", value: "GET"),
            HeaderField(name: ":scheme", value: "https"),
            HeaderField(name: ":authority", value: "example.com"),
            HeaderField(name: ":path", value: "/")
        ]
        return http3RequestInjections(request: request, base: base)
            .merging(
                http3ControlInjections(control: control, secondUni: secondUni, push: pushStream)
            ) {
                first, _ in first
            }
            .merging(
                qpackInjections(
                    request: request, encoder: encoder, decoder: decoder, secondUni: secondUni
                )
            ) {
                first, _ in first
            }
    }

    /// Request-stream message + framing malformations (RFC 9114 §4 / §7.1).
    private func http3RequestInjections(
        request: QUICStreamID, base: [HeaderField]
    ) -> [String: (inout HTTP3Connection) -> Void] {
        [
            "DATA received before HEADERS": { connection in
                _ = try? connection.receive(request, self.frame(.data, [0, 0]), fin: false)
            },
            "a DATA frame before any HEADERS on a request stream": { connection in
                _ = try? connection.receive(request, self.frame(.data, [0, 0]), fin: false)
            },
            "a duplicated pseudo-header field": { connection in
                let fields = [
                    HeaderField(name: ":method", value: "GET"),
                    HeaderField(name: ":method", value: "GET"),
                    HeaderField(name: ":scheme", value: "https"),
                    HeaderField(name: ":path", value: "/")
                ]
                _ = try? connection.receive(
                    request,
                    self.requestStream(self.fieldSection(fields)),
                    fin: true
                )
            },
            "a mandatory pseudo-header field is absent": { connection in
                let fields = [
                    HeaderField(name: ":method", value: "GET"),
                    HeaderField(name: ":scheme", value: "https")
                ]
                _ = try? connection.receive(
                    request,
                    self.requestStream(self.fieldSection(fields)),
                    fin: true
                )
            },
            "a prohibited pseudo-header field is present": { connection in
                _ = try? connection.receive(
                    request,
                    self.requestStream(
                        self.fieldSection(base + [HeaderField(name: ":unknown", value: "x")])
                    ),
                    fin: true
                )
            },
            "a pseudo-header field after regular fields": { connection in
                let fields = [
                    HeaderField(name: ":method", value: "GET"),
                    HeaderField(name: ":scheme", value: "https"),
                    HeaderField(name: ":path", value: "/"),
                    HeaderField(name: "x-test", value: "1"),
                    HeaderField(name: ":authority", value: "example.com")
                ]
                _ = try? connection.receive(
                    request,
                    self.requestStream(self.fieldSection(fields)),
                    fin: true
                )
            },
            "a connection-specific header field": { connection in
                _ = try? connection.receive(
                    request,
                    self.requestStream(
                        self.fieldSection(
                            base + [HeaderField(name: "connection", value: "keep-alive")]
                        )
                    ),
                    fin: true
                )
            },
            "a TE header field with a value other than trailers": { connection in
                _ = try? connection.receive(
                    request,
                    self.requestStream(
                        self.fieldSection(base + [HeaderField(name: "te", value: "gzip")])
                    ),
                    fin: true
                )
            },
            "a content-length not matching the DATA length": { connection in
                let fields = base + [HeaderField(name: "content-length", value: "3")]
                _ = try? connection.receive(
                    request,
                    self.requestStream(self.fieldSection(fields), body: Array("hello".utf8)),
                    fin: true
                )
            },
            "a frame whose length runs past the stream": { connection in
                // HEADERS declaring length 10 but delivering 3 octets, then FIN.
                _ = try? connection.receive(request, [0x01, 0x0A, 0x00, 0x00, 0x51], fin: true)
            },
            "a GOAWAY frame on a request stream": { connection in
                _ = try? connection.receive(
                    request,
                    self.frame(.goAway, self.varint(0)),
                    fin: false
                )
            },
            "a SETTINGS frame on a request stream": { connection in
                _ = try? connection.receive(request, self.frame(.settings, []), fin: false)
            },
            "CANCEL_PUSH received on a request stream": { connection in
                _ = try? connection.receive(
                    request,
                    self.frame(.cancelPush, self.varint(0)),
                    fin: false
                )
            }
        ]
    }

    /// Control-stream + unidirectional-stream malformations (RFC 9114 §6.2 / §7.2).
    private func http3ControlInjections(
        control: QUICStreamID, secondUni: QUICStreamID, push: QUICStreamID
    ) -> [String: (inout HTTP3Connection) -> Void] {
        [
            "the first control-stream frame is not SETTINGS": { connection in
                _ = try? connection.receive(
                    control,
                    [0x00] + self.frame(.goAway, self.varint(0)),
                    fin: false
                )
            },
            "a DATA frame on the control stream": { connection in
                _ = try? connection.receive(
                    control,
                    self.controlPreamble() + self.frame(.data, [1]),
                    fin: false
                )
            },
            "a HEADERS frame on the control stream": { connection in
                _ = try? connection.receive(
                    control,
                    self.controlPreamble() + self.frame(.headers, [1]),
                    fin: false
                )
            },
            "a PUSH_PROMISE frame on the control stream": { connection in
                _ = try? connection.receive(
                    control,
                    self.controlPreamble() + self.frame(.pushPromise, [1]),
                    fin: false
                )
            },
            "a second SETTINGS frame": { connection in
                _ = try? connection.receive(
                    control,
                    self.controlPreamble() + self.frame(.settings, []),
                    fin: false
                )
            },
            "an HTTP/2-only setting identifier is present": { connection in
                _ = try? connection.receive(
                    control,
                    [0x00] + self.frame(.settings, self.settingsPayload([(0x02, 1)])),
                    fin: false
                )
            },
            "a reserved HTTP/2 setting identifier (0x02/0x03/0x04/0x05)": { connection in
                _ = try? connection.receive(
                    control,
                    [0x00] + self.frame(.settings, self.settingsPayload([(0x03, 1)])),
                    fin: false
                )
            },
            "a duplicate setting identifier in one SETTINGS frame": { connection in
                _ = try? connection.receive(
                    control,
                    [0x00] + self.frame(.settings, self.settingsPayload([(0x06, 1), (0x06, 2)])),
                    fin: false
                )
            },
            "a second control stream is created": { connection in
                _ = try? connection.receive(control, [0x00], fin: false)
                _ = try? connection.receive(secondUni, [0x00], fin: false)
            },
            "the peer's control stream is closed": { connection in
                _ = try? connection.receive(control, self.controlPreamble(), fin: true)
            },
            "a GOAWAY identifier that increases": { connection in
                _ = try? connection.receive(
                    control,
                    self.controlPreamble() + self.frame(.goAway, self.varint(4)),
                    fin: false
                )
                _ = try? connection.receive(
                    control,
                    self.frame(.goAway, self.varint(8)),
                    fin: false
                )
            },
            "a Push ID greater than MAX_PUSH_ID": { connection in
                _ = try? connection.receive(
                    control,
                    self.controlPreamble() + self.frame(.cancelPush, self.varint(0)),
                    fin: false
                )
            },
            "a CANCEL_PUSH for a Push ID above MAX_PUSH_ID": { connection in
                _ = try? connection.receive(
                    control,
                    self.controlPreamble() + self.frame(.cancelPush, self.varint(0)),
                    fin: false
                )
            },
            "a server receives a client-initiated push stream": { connection in
                _ = try? connection.receive(push, [0x01], fin: false)
            }
        ]
    }

    /// QPACK field-section + instruction-stream malformations (RFC 9204 §3 / §4).
    private func qpackInjections(
        request: QUICStreamID, encoder: QUICStreamID, decoder: QUICStreamID, secondUni: QUICStreamID
    ) -> [String: (inout HTTP3Connection) -> Void] {
        [
            "a field line references an invalid static-table index": { connection in
                _ = try? connection.receive(
                    request,
                    self.frame(.headers, [0x00, 0x00, 0xFF, 0x24]),
                    fin: true
                )
            },
            "a reference to an evicted dynamic-table entry": { connection in
                // An indexed dynamic reference (T=0) with the table disabled.
                _ = try? connection.receive(
                    request,
                    self.frame(.headers, [0x00, 0x00, 0x80]),
                    fin: true
                )
            },
            "a Required Insert Count beyond the blocked-streams limit": { connection in
                // A non-zero Required Insert Count in the §4.5.1 prefix.
                _ = try? connection.receive(request, self.frame(.headers, [0x05, 0x00]), fin: true)
            },
            "a Set Dynamic Table Capacity above the limit": { connection in
                // Set Capacity 5000 > the advertised 4096 (a `001`-prefix integer, §4.3.1).
                _ = try? connection.receive(encoder, [0x02, 0x3F, 0xE9, 0x26], fin: false)
            },
            "an encoder-stream instruction referencing an evicted entry": { connection in
                // Insert With Name Reference, dynamic index 5 (T=0) with an empty value — but the table
                // holds no such entry, so the reference is invalid (§4.3.2).
                _ = try? connection.receive(encoder, [0x02, 0x85, 0x00], fin: false)
            },
            "a critical (encoder) stream is closed": { connection in
                _ = try? connection.receive(encoder, [0x02], fin: true)
            },
            "an Insert Count Increment of 0": { connection in
                _ = try? connection.receive(decoder, [0x03, 0x00], fin: false)
            },
            "an Insert Count Increment beyond what the encoder sent": { connection in
                _ = try? connection.receive(decoder, [0x03, 0x05], fin: false)
            },
            "a second QPACK encoder or decoder stream": { connection in
                _ = try? connection.receive(encoder, [0x02], fin: false)
                _ = try? connection.receive(secondUni, [0x02], fin: false)
            }
        ]
    }
}
