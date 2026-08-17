//
//  TLSServerConnection+ClientHello.swift
//  HTTPTLS
//
//  RFC 8446 §4.1.2/§4.2 — ClientHello processing: version gate (§4.2.1, Appendices D.2/D.5),
//  the §4.1.1 server-preference negotiation of suite/group/schemes/ALPN, the §4.1.4
//  HelloRetryRequest round (at most once), and the retry-contract checks of §4.1.2. PSK
//  resumption is +Resumption's; the flight that answers is +Flight's.
//

internal import Crypto

extension TLSServerConnection {
    /// Processes an initial or retried ClientHello end to end.
    mutating func processClientHello(
        _ message: TLSHandshakeCoalescer.Message
    ) async throws(TLSHandshakeError) {
        let hello = try TLSClientHello.parse(message)
        try validateVersion(hello)
        guard hello.compressionMethods == [0] else {
            // §4.1.2: "If a TLS 1.3 ClientHello is received with any other value in this
            // field, the server MUST abort the handshake with an illegal_parameter alert."
            throw .illegalParameter("legacy_compression_methods")
        }
        let suite = try selectSuite(hello)
        if sentHelloRetry {
            try validateRetriedHello(hello, suite: suite)
        }
        guard let groups = hello.supportedGroups, !groups.isEmpty else {
            throw .missingExtension(.supportedGroups)  // §9.2 for (EC)DHE
        }
        guard let shares = hello.keyShares else {
            throw .missingExtension(.keyShare)  // §9.2 (an EMPTY list is present and legal)
        }
        for share in shares where !groups.contains(share.group) {
            // §4.2.8: "Clients MUST NOT offer any KeyShareEntry ... for groups not listed in
            // the client's supported_groups" — this server checks.
            throw .illegalParameter("key_share group not in supported_groups")
        }
        let group = try selectGroup(clientGroups: groups, shares: shares)
        guard let share = shares.first(where: { $0.group == group }) else {
            try sendHelloRetryRequest(hello, message: message, suite: suite, group: group)
            return
        }
        try negotiateApplicationParameters(hello)
        try await completeHandshakeFlight(
            hello, message: message, suite: suite, group: group, clientShare: share
        )
    }

    /// §4.2.1 + Appendix D: the version gate of a 1.3-only server.
    private func validateVersion(_ hello: TLSClientHello) throws(TLSHandshakeError) {
        guard hello.legacyVersion > 0x0300 else {
            // Appendix D.5: "Any endpoint receiving a Hello message with
            // ClientHello.legacy_version ... set to 0x0300 MUST abort the handshake with a
            // protocol_version alert."
            throw .unsupportedVersion
        }
        guard let versions = hello.supportedVersions else {
            // Appendix D.2: without supported_versions the server "MUST negotiate the minimum
            // of ClientHello.legacy_version and TLS 1.2" — this server supports neither, and
            // then "MUST abort the handshake with a protocol_version alert".
            throw .unsupportedVersion
        }
        guard versions.contains(0x0304) else {
            // §4.2.1: "Servers MUST only select a version of TLS present in that extension" —
            // with no 1.2 to fall back to, the D.2 abort applies.
            throw .unsupportedVersion
        }
    }

    /// §4.1.1 suite negotiation: first configured suite the client offers.
    private func selectSuite(
        _ hello: TLSClientHello
    ) throws(TLSHandshakeError)
        -> TLSCipherSuite
    {
        for candidate in configuration.cipherSuites
        where hello.cipherSuites.contains(candidate.rawValue) {
            return candidate
        }
        throw .negotiationFailed("cipher suites")  // §4.1.1 handshake_failure
    }

    /// §4.2.8 group selection, server preference: among mutually supported implemented
    /// groups, prefer the first with a client share (avoiding a gratuitous HRR); with no
    /// share anywhere, the first common group — the HRR target.
    private func selectGroup(
        clientGroups: [TLSNamedGroup], shares: [TLSKeyShareEntry]
    ) throws(TLSHandshakeError) -> TLSNamedGroup {
        if let retryGroup {
            // §4.2.8/§4.1.4: after our HRR the client MUST supply a share for exactly the
            // group we named; anything else is illegal_parameter.
            guard shares.contains(where: { $0.group == retryGroup }) else {
                throw .illegalParameter("retried ClientHello lacks the requested key share")
            }
            return retryGroup
        }
        let common = configuration.groups.filter {
            $0.isImplemented && clientGroups.contains($0)
        }
        guard let first = common.first else {
            throw .negotiationFailed("groups")  // §4.1.1
        }
        return common.first { group in shares.contains { $0.group == group } } ?? first
    }

    /// §4.1.4: sends the single permitted HelloRetryRequest naming `group`.
    private mutating func sendHelloRetryRequest(
        _ hello: TLSClientHello,
        message: TLSHandshakeCoalescer.Message,
        suite: TLSCipherSuite,
        group: TLSNamedGroup
    ) throws(TLSHandshakeError) {
        guard !sentHelloRetry else {
            throw .internalError("second HelloRetryRequest")  // §4.1.4 — unreachable
        }
        var running = TLSTranscriptHash(suite.hash)
        running.append(message.raw)
        let clientHello1Hash = running.currentHash
        running.collapseForHelloRetry()  // §4.4.1's message_hash replacement
        let cookie = configuration.cookieProvider?(clientHello1Hash)
        let retry = TLSServerHelloEncoder.helloRetryRequest(
            sessionIDEcho: hello.legacySessionID,
            suite: suite,
            selectedGroup: group,
            cookie: cookie
        )
        running.append(retry)
        transcript = running
        try emit(handshake: retry)
        emitCompatibilityCCSIfNeeded()  // D.4: right after the first server message
        selectedSuite = suite
        sentHelloRetry = true
        retryGroup = group
        sentCookie = cookie
        state = .expectingRetriedClientHello
    }

    /// §4.1.2's retry contract: same suite selection, the cookie echoed exactly, early_data
    /// removed.
    private func validateRetriedHello(
        _ hello: TLSClientHello, suite: TLSCipherSuite
    ) throws(TLSHandshakeError) {
        guard suite == selectedSuite else {
            // §4.1.4: "servers MUST ensure that they negotiate the same cipher suite when
            // receiving a conformant updated ClientHello".
            throw .illegalParameter("cipher suite changed after HelloRetryRequest")
        }
        if let sentCookie {
            guard let echoed = hello.cookie else {
                throw .missingExtension(.cookie)  // §4.2.2: "MUST copy ... to the new hello"
            }
            guard echoed == sentCookie else {
                throw .illegalParameter("cookie")
            }
        }
        guard !hello.offeredEarlyData else {
            // §4.1.2: the retried hello changes only what HRR demands, "removing the
            // early_data extension".
            throw .illegalParameter("early_data in retried ClientHello")
        }
    }

    /// RFC 7301 / RFC 6066 / RFC 8449: the application-layer parameters.
    private mutating func negotiateApplicationParameters(
        _ hello: TLSClientHello
    ) throws(TLSHandshakeError) {
        clientServerName = hello.serverName
        if !configuration.alpnProtocols.isEmpty, let offered = hello.alpnProtocols {
            guard let chosen = configuration.alpnProtocols.first(where: offered.contains)
            else {
                throw .noApplicationProtocol  // RFC 7301 §3.2
            }
            selectedAlpn = chosen
        }
        if let limit = hello.recordSizeLimit {
            guard limit >= 64 else {
                // RFC 8449 §4: "Endpoints MUST NOT send a record_size_limit smaller than 64
                // ... MUST treat receipt of a smaller value as a fatal error and generate an
                // illegal_parameter alert."
                throw .illegalParameter("record_size_limit below 64")
            }
            if configuration.recordSizeLimit != nil {
                // Negotiated both ways — honor the peer's limit outbound (RFC 8449 §4; the
                // limit covers the whole TLSInnerPlaintext, hence the −1 for the type octet).
                peerRecordSizeLimit = limit
                record.maxOutboundFragmentLength = min(
                    limit - 1, TLSRecordLimits.maxPlaintextLength
                )
            }
        }
    }

    /// D.4: the middlebox-compatibility CCS, once, right after the first server message.
    mutating func emitCompatibilityCCSIfNeeded() {
        guard configuration.middleboxCompatibilityMode, !sentCompatibilityCCS else {
            return
        }
        try? record.sendChangeCipherSpec()
        sentCompatibilityCCS = true
    }
}
