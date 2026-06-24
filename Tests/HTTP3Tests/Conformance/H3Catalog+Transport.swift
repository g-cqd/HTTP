//
//  H3Catalog+Transport.swift
//  HTTP3Tests
//
//  The h3spec QUIC-transport (RFC 9000) rows of the conformance catalog, split out of
//  H3ConformanceCatalog.swift so each file stays within the line budget. These 27 checks are
//  `.platform`-stamped: enforced by Apple's QUIC stack beneath the engine, so they are acknowledged by
//  ``H3SpecTests`` rather than driven from Swift.
//

extension H3Conformance {
    // MARK: h3spec — QUIC transport (RFC 9000), 27 checks

    static let quicTransport: [H3Check] = [
        H3Check(
            .h3spec,
            .quicTransport,
            "§4.1",
            "STREAM frame with an excessive offset",
            "FLOW_CONTROL_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§4.6",
            "stream ID exceeding the advertised limit",
            "STREAM_LIMIT_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§7.3",
            "initial_source_connection_id is missing",
            "TRANSPORT_PARAMETER_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§18.2",
            "original_destination_connection_id is received",
            "TRANSPORT_PARAMETER_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§18.2",
            "preferred_address is received",
            "TRANSPORT_PARAMETER_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§18.2",
            "retry_source_connection_id is received",
            "TRANSPORT_PARAMETER_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§18.2",
            "stateless_reset_token is received",
            "TRANSPORT_PARAMETER_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§7.4/§18.2",
            "max_udp_payload_size below 1200",
            "TRANSPORT_PARAMETER_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§7.4/§18.2",
            "ack_delay_exponent above 20",
            "TRANSPORT_PARAMETER_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§7.4/§18.2",
            "max_ack_delay of 2^14 or more",
            "TRANSPORT_PARAMETER_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§12.4",
            "a frame of unknown type",
            "FRAME_ENCODING_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§12.4",
            "a packet carrying no frames",
            "PROTOCOL_VIOLATION"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§17.2",
            "reserved bits in a Handshake packet are non-zero",
            "PROTOCOL_VIOLATION"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§17.2.4",
            "PATH_CHALLENGE in a Handshake packet",
            "PROTOCOL_VIOLATION"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§17.2",
            "reserved bits in a Short header are non-zero",
            "PROTOCOL_VIOLATION"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§19.4",
            "RESET_STREAM for a send-only stream",
            "STREAM_STATE_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§19.5",
            "STOP_SENDING for a non-existing stream",
            "STREAM_STATE_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§19.7",
            "NEW_TOKEN received by a server",
            "PROTOCOL_VIOLATION"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§19.8",
            "STREAM frame for an uncreated locally-initiated stream",
            "STREAM_STATE_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§19.8",
            "STREAM frame for a send-only stream",
            "STREAM_STATE_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§19.10",
            "MAX_STREAM_DATA for an uncreated stream",
            "STREAM_STATE_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§19.10",
            "MAX_STREAM_DATA for a receive-only stream",
            "STREAM_STATE_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§19.11",
            "an invalid MAX_STREAMS (above 2^60)",
            "FRAME_ENCODING_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§19.14",
            "an invalid STREAMS_BLOCKED (above 2^60)",
            "FRAME_ENCODING_ERROR or STREAM_LIMIT_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§19.15",
            "NEW_CONNECTION_ID with Retire_Prior_To past the sequence",
            "FRAME_ENCODING_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§19.15",
            "NEW_CONNECTION_ID with a zero-length connection ID",
            "FRAME_ENCODING_ERROR"
        ),
        H3Check(
            .h3spec,
            .quicTransport,
            "§19.20",
            "HANDSHAKE_DONE received by a server",
            "PROTOCOL_VIOLATION"
        )
    ]
}
