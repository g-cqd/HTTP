//
//  H3ConformanceCatalog.swift
//  HTTP3Tests
//
//  The HTTP/3 conformance catalog — a living, type-checked spec mirroring `h3spec`
//  (kazu-yamamoto/h3spec, the HTTP/3 analogue of h2spec) plus the RFC 9114 / RFC 9204 MUSTs h3spec
//  does not cover. The HTTP/3 engine is milestone M7 and is not built yet, so this is staging: every
//  engine-driven check is `.pending` and run as a disabled test (see H3SpecTests.swift). As the M7
//  engine lands, checks flip to `.supported` and their disabled tests become live drive-and-assert
//  cases — each "inject one malformation, assert the connection/stream closes with `expect`".
//
//  Tolerance (from h3spec, per RFC 9000 §11 / RFC 9114 §8): a server MAY substitute a generic
//  PROTOCOL_VIOLATION / INTERNAL_ERROR (transport) or H3_GENERAL_PROTOCOL_ERROR / H3_INTERNAL_ERROR
//  (application) for a specific code; the eventual live assertions must accept those equivalents.
//

/// The protocol layer a conformance check exercises.
enum H3Layer: String, Sendable, CaseIterable {
    case quicTransport = "QUIC transport (RFC 9000)"
    case quicTLS = "QUIC-TLS (RFC 9001)"
    case http3 = "HTTP/3 (RFC 9114)"
    case qpack = "QPACK (RFC 9204)"
}

/// Where a check originates: the h3spec tool, or an RFC MUST h3spec leaves uncovered.
enum H3Source: String, Sendable {
    case h3spec
    case rfc9000
    case rfc9001
    case rfc9114
    case rfc9204
}

/// Whether the engine implements the behavior yet (drives whether the test is live or disabled).
enum H3Status: Sendable {
    case pending  // M7 not implemented — the check is staged, its test disabled
    case supported  // implemented by the Swift engine — the check runs live as a drive-and-assert
    case platform  // enforced by Apple's QUIC/TLS stack (RFC 9000/9001), not the Swift engine
}

/// One HTTP/3 conformance check: the malformation to inject and the error the endpoint must answer with.
struct H3Check: Sendable {
    let source: H3Source
    let layer: H3Layer
    /// The RFC section (and h3spec tag where applicable).
    let section: String
    /// The behavior under test (verbatim from h3spec where it is the source).
    let title: String
    /// The expected endpoint reaction — the error code (with its wire value for HTTP/3 / QPACK codes).
    let expect: String
    var status: H3Status

    init(
        _ source: H3Source, _ layer: H3Layer, _ section: String, _ title: String, _ expect: String,
        status: H3Status = .pending
    ) {
        self.source = source
        self.layer = layer
        self.section = section
        self.title = title
        self.expect = expect
        self.status = status
    }
}

/// The HTTP/3 + QPACK conformance catalog and the RFC error-code registries.
enum H3Conformance {
    /// Every staged check: the 49 active h3spec cases plus the RFC 9114/9204 MUST-gaps h3spec omits.
    ///
    /// As of M7 the status is stamped by layer: the HTTP/3 (RFC 9114) and QPACK (RFC 9204) rows are
    /// `.supported` — the Swift engine implements them and ``H3SpecTests`` drives each one — while the
    /// QUIC-transport (RFC 9000) and QUIC-TLS (RFC 9001) rows are `.platform`: they are enforced by
    /// Apple's QUIC stack beneath the engine and cannot be exercised from Swift, so they are not driven.
    static let checks: [H3Check] = (quicTransport + quicTLS + http3 + qpack + gaps).map(stamped)

    /// Stamps a check's status from its layer (engine-implemented vs platform-enforced).
    private static func stamped(_ check: H3Check) -> H3Check {
        var stamped = check
        switch check.layer {
            case .http3, .qpack: stamped.status = .supported
            case .quicTransport, .quicTLS: stamped.status = .platform
        }
        return stamped
    }

    // MARK: h3spec — QUIC transport (RFC 9000), 27 checks

    private static let quicTransport: [H3Check] = [
        H3Check(
            .h3spec, .quicTransport, "§4.1",
            "STREAM frame with an excessive offset", "FLOW_CONTROL_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§4.6",
            "stream ID exceeding the advertised limit", "STREAM_LIMIT_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§7.3",
            "initial_source_connection_id is missing", "TRANSPORT_PARAMETER_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§18.2",
            "original_destination_connection_id is received", "TRANSPORT_PARAMETER_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§18.2",
            "preferred_address is received", "TRANSPORT_PARAMETER_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§18.2",
            "retry_source_connection_id is received", "TRANSPORT_PARAMETER_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§18.2",
            "stateless_reset_token is received", "TRANSPORT_PARAMETER_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§7.4/§18.2",
            "max_udp_payload_size below 1200", "TRANSPORT_PARAMETER_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§7.4/§18.2",
            "ack_delay_exponent above 20", "TRANSPORT_PARAMETER_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§7.4/§18.2",
            "max_ack_delay of 2^14 or more", "TRANSPORT_PARAMETER_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§12.4",
            "a frame of unknown type", "FRAME_ENCODING_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§12.4",
            "a packet carrying no frames", "PROTOCOL_VIOLATION"),
        H3Check(
            .h3spec, .quicTransport, "§17.2",
            "reserved bits in a Handshake packet are non-zero", "PROTOCOL_VIOLATION"),
        H3Check(
            .h3spec, .quicTransport, "§17.2.4",
            "PATH_CHALLENGE in a Handshake packet", "PROTOCOL_VIOLATION"),
        H3Check(
            .h3spec, .quicTransport, "§17.2",
            "reserved bits in a Short header are non-zero", "PROTOCOL_VIOLATION"),
        H3Check(
            .h3spec, .quicTransport, "§19.4",
            "RESET_STREAM for a send-only stream", "STREAM_STATE_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§19.5",
            "STOP_SENDING for a non-existing stream", "STREAM_STATE_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§19.7",
            "NEW_TOKEN received by a server", "PROTOCOL_VIOLATION"),
        H3Check(
            .h3spec, .quicTransport, "§19.8",
            "STREAM frame for an uncreated locally-initiated stream", "STREAM_STATE_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§19.8",
            "STREAM frame for a send-only stream", "STREAM_STATE_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§19.10",
            "MAX_STREAM_DATA for an uncreated stream", "STREAM_STATE_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§19.10",
            "MAX_STREAM_DATA for a receive-only stream", "STREAM_STATE_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§19.11",
            "an invalid MAX_STREAMS (above 2^60)", "FRAME_ENCODING_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§19.14",
            "an invalid STREAMS_BLOCKED (above 2^60)", "FRAME_ENCODING_ERROR or STREAM_LIMIT_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§19.15",
            "NEW_CONNECTION_ID with Retire_Prior_To past the sequence", "FRAME_ENCODING_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§19.15",
            "NEW_CONNECTION_ID with a zero-length connection ID", "FRAME_ENCODING_ERROR"),
        H3Check(
            .h3spec, .quicTransport, "§19.20",
            "HANDSHAKE_DONE received by a server", "PROTOCOL_VIOLATION")
    ]

    // MARK: h3spec — QUIC-TLS (RFC 9001), 7 checks

    private static let quicTLS: [H3Check] = [
        H3Check(
            .h3spec, .quicTLS, "§6",
            "KeyUpdate in a Handshake packet", "TLS unexpected_message"),
        H3Check(
            .h3spec, .quicTLS, "§6",
            "KeyUpdate in a 1-RTT packet", "TLS unexpected_message"),
        H3Check(
            .h3spec, .quicTLS, "§8.1",
            "no supported application protocol (ALPN)", "TLS no_application_protocol"),
        H3Check(
            .h3spec, .quicTLS, "§8.2",
            "quic_transport_parameters extension absent", "TLS missing_extension"),
        H3Check(
            .h3spec, .quicTLS, "§8.2",
            "quic_transport_parameters extension under the wrong id", "TLS missing_extension"),
        H3Check(
            .h3spec, .quicTLS, "§8.3",
            "EndOfEarlyData received", "TLS unexpected_message"),
        H3Check(
            .h3spec, .quicTLS, "§8.3",
            "CRYPTO in a 0-RTT packet (requires a 0-RTT ticket)", "PROTOCOL_VIOLATION")
    ]

    // MARK: h3spec — HTTP/3 (RFC 9114), 11 checks

    private static let http3: [H3Check] = [
        H3Check(
            .h3spec, .http3, "§4.1",
            "DATA received before HEADERS", "H3_FRAME_UNEXPECTED (0x0105)"),
        H3Check(
            .h3spec, .http3, "§4.1.1",
            "a duplicated pseudo-header field", "H3_MESSAGE_ERROR (0x010e)"),
        H3Check(
            .h3spec, .http3, "§4.1.3",
            "a mandatory pseudo-header field is absent", "H3_MESSAGE_ERROR (0x010e)"),
        H3Check(
            .h3spec, .http3, "§4.1.3",
            "a prohibited pseudo-header field is present", "H3_MESSAGE_ERROR (0x010e)"),
        H3Check(
            .h3spec, .http3, "§4.1.3",
            "a pseudo-header field after regular fields", "H3_MESSAGE_ERROR (0x010e)"),
        H3Check(
            .h3spec, .http3, "§6.2.1",
            "the first control-stream frame is not SETTINGS", "H3_MISSING_SETTINGS (0x010a)"),
        H3Check(
            .h3spec, .http3, "§7.2.1",
            "a DATA frame on the control stream", "H3_FRAME_UNEXPECTED (0x0105)"),
        H3Check(
            .h3spec, .http3, "§7.2.2",
            "a HEADERS frame on the control stream", "H3_FRAME_UNEXPECTED (0x0105)"),
        H3Check(
            .h3spec, .http3, "§7.2.4",
            "a second SETTINGS frame", "H3_FRAME_UNEXPECTED (0x0105)"),
        H3Check(
            .h3spec, .http3, "§7.2.4.1",
            "an HTTP/2-only setting identifier is present", "H3_SETTINGS_ERROR (0x0109)"),
        H3Check(
            .h3spec, .http3, "§7.2.5",
            "CANCEL_PUSH received on a request stream", "H3_FRAME_UNEXPECTED (0x0105)")
    ]

    // MARK: h3spec — QPACK (RFC 9204), 4 checks

    private static let qpack: [H3Check] = [
        H3Check(
            .h3spec, .qpack, "§3.1",
            "a field line references an invalid static-table index",
            "QPACK_DECOMPRESSION_FAILED (0x0200)"),
        H3Check(
            .h3spec, .qpack, "§4.1.3/§4.3.1",
            "a Set Dynamic Table Capacity above the limit", "QPACK_ENCODER_STREAM_ERROR (0x0201)"),
        H3Check(
            .h3spec, .qpack, "§4.2",
            "a critical (encoder) stream is closed", "H3_CLOSED_CRITICAL_STREAM (0x0104)"),
        H3Check(
            .h3spec, .qpack, "§4.4.3",
            "an Insert Count Increment of 0", "QPACK_DECODER_STREAM_ERROR (0x0202)")
    ]

    // MARK: RFC 9114 / 9204 MUSTs h3spec does not cover (coverage gaps to add for M7)

    private static let gaps: [H3Check] = [
        H3Check(
            .rfc9114, .http3, "§6.2.1",
            "a second control stream is created", "H3_STREAM_CREATION_ERROR (0x0103)"),
        H3Check(
            .rfc9114, .http3, "§6.2.1",
            "the peer's control stream is closed", "H3_CLOSED_CRITICAL_STREAM (0x0104)"),
        H3Check(
            .rfc9114, .http3, "§7.2.5",
            "a PUSH_PROMISE frame on the control stream", "H3_FRAME_UNEXPECTED (0x0105)"),
        H3Check(
            .rfc9114, .http3, "§5.2/§7.2.6",
            "a GOAWAY identifier that increases", "H3_ID_ERROR (0x0108)"),
        H3Check(
            .rfc9114, .http3, "§7.2.7",
            "a Push ID greater than MAX_PUSH_ID", "H3_ID_ERROR (0x0108)"),
        H3Check(
            .rfc9114, .http3, "§7.1",
            "a frame whose length runs past the stream", "H3_FRAME_ERROR (0x0106)"),
        H3Check(
            .rfc9114, .http3, "§4.2",
            "a connection-specific header field", "H3_MESSAGE_ERROR (0x010e)"),
        H3Check(
            .rfc9114, .http3, "§4.2",
            "a TE header field with a value other than trailers", "H3_MESSAGE_ERROR (0x010e)"),
        H3Check(
            .rfc9114, .http3, "§4.1.2",
            "a content-length not matching the DATA length", "H3_MESSAGE_ERROR (0x010e)"),
        H3Check(
            .rfc9204, .qpack, "§4.2",
            "a second QPACK encoder or decoder stream", "H3_STREAM_CREATION_ERROR (0x0103)"),
        H3Check(
            .rfc9204, .qpack, "§3.1",
            "a reference to an evicted dynamic-table entry", "QPACK_DECOMPRESSION_FAILED (0x0200)"),
        H3Check(
            .rfc9204, .qpack, "§2.1.1",
            "a Required Insert Count beyond the blocked-streams limit",
            "QPACK_DECOMPRESSION_FAILED (0x0200)"),
        // Frame-on-wrong-stream and sequence rules (RFC 9114 §4.1 / §7.2) the h3spec list omits.
        H3Check(
            .rfc9114, .http3, "§4.1",
            "a DATA frame before any HEADERS on a request stream", "H3_FRAME_UNEXPECTED (0x0105)"),
        H3Check(
            .rfc9114, .http3, "§7.2.6",
            "a GOAWAY frame on a request stream", "H3_FRAME_UNEXPECTED (0x0105)"),
        H3Check(
            .rfc9114, .http3, "§7.2.4",
            "a SETTINGS frame on a request stream", "H3_FRAME_UNEXPECTED (0x0105)"),
        H3Check(
            .rfc9114, .http3, "§6.2.2",
            "a server receives a client-initiated push stream",
            "H3_STREAM_CREATION_ERROR (0x0103)"),
        H3Check(
            .rfc9114, .http3, "§7.2.3",
            "a CANCEL_PUSH for a Push ID above MAX_PUSH_ID", "H3_ID_ERROR (0x0108)"),
        // SETTINGS validity (RFC 9114 §7.2.4 / §7.2.4.1).
        H3Check(
            .rfc9114, .http3, "§7.2.4",
            "a duplicate setting identifier in one SETTINGS frame", "H3_SETTINGS_ERROR (0x0109)"),
        H3Check(
            .rfc9114, .http3, "§7.2.4.1",
            "a reserved HTTP/2 setting identifier (0x02/0x03/0x04/0x05)",
            "H3_SETTINGS_ERROR (0x0109)"),
        // The two QPACK error codes h3spec never triggers (RFC 9204 §3.1 / §4.4.3).
        H3Check(
            .rfc9204, .qpack, "§3.1",
            "an encoder-stream instruction referencing an evicted entry",
            "QPACK_ENCODER_STREAM_ERROR (0x0201)"),
        H3Check(
            .rfc9204, .qpack, "§4.4.3",
            "an Insert Count Increment beyond what the encoder sent",
            "QPACK_DECODER_STREAM_ERROR (0x0202)")
    ]

    // MARK: RFC error-code registries (locked by H3SpecTests so the wire values cannot drift)

    /// RFC 9114 §8.1 — HTTP/3 error codes.
    static let http3ErrorCodes: [(name: String, code: UInt32)] = [
        ("H3_NO_ERROR", 0x0100), ("H3_GENERAL_PROTOCOL_ERROR", 0x0101),
        ("H3_INTERNAL_ERROR", 0x0102),
        ("H3_STREAM_CREATION_ERROR", 0x0103), ("H3_CLOSED_CRITICAL_STREAM", 0x0104),
        ("H3_FRAME_UNEXPECTED", 0x0105), ("H3_FRAME_ERROR", 0x0106), ("H3_EXCESSIVE_LOAD", 0x0107),
        ("H3_ID_ERROR", 0x0108), ("H3_SETTINGS_ERROR", 0x0109), ("H3_MISSING_SETTINGS", 0x010a),
        ("H3_REQUEST_REJECTED", 0x010b), ("H3_REQUEST_CANCELLED", 0x010c),
        ("H3_REQUEST_INCOMPLETE", 0x010d), ("H3_MESSAGE_ERROR", 0x010e),
        ("H3_CONNECT_ERROR", 0x010f), ("H3_VERSION_FALLBACK", 0x0110)
    ]

    /// RFC 9204 §6 — QPACK error codes.
    static let qpackErrorCodes: [(name: String, code: UInt32)] = [
        ("QPACK_DECOMPRESSION_FAILED", 0x0200), ("QPACK_ENCODER_STREAM_ERROR", 0x0201),
        ("QPACK_DECODER_STREAM_ERROR", 0x0202)
    ]
}
