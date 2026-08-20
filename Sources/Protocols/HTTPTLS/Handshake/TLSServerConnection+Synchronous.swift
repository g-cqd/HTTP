//
//  TLSServerConnection+Synchronous.swift
//  HTTPTLS
//
//  Phase 3d — the FULL synchronous drive: every state ``receive(_:)`` handles, without
//  suspension, for callers that hold a lock across the call (the portable TLS backbone's
//  engine adapter drives this machine under a `Mutex`, where an `await` is unspellable).
//  The async surface exists for hardware/remote identity seams; when the seams in play are
//  synchronous — ``TLSSynchronousIdentityProvider``, ``TLSSynchronousClientChainValidator``,
//  which every local implementation in this package conforms to — the handshake itself
//  never needed to suspend. A handshake that resolves an ASYNC-only seam through this drive
//  fails closed (`internal_error`, funneled) instead of degrading to a hidden wait.
//
//  Everything below the dispatch is SHARED with the async drive — one record splitter, one
//  flight builder, one funnel — so the two drives cannot disagree about a byte; only the
//  seam-resolution steps differ, and those are the two spots this file owns.
//

extension TLSServerConnection {
    /// Feeds inbound wire octets without suspension; returns the events they complete.
    ///
    /// The synchronous twin of ``receive(_:)`` for synchronous identity/trust seams; any
    /// throw is fatal and already funneled (the alert is queued, the state terminal).
    public mutating func receiveSynchronously(
        _ bytes: [UInt8]
    ) throws(TLSHandshakeError) -> [TLSServerEvent] {
        guard !state.isTerminal else {
            throw TLSHandshakeError.connectionClosed
        }
        var events: [TLSServerEvent] = []
        var cursor = bytes.startIndex
        do {
            while !state.isTerminal,
                let recordEvents = try pumpOneRecord(bytes, cursor: &cursor)
            {
                for event in recordEvents {
                    try handleFullSynchronous(event, into: &events)
                    if state.isTerminal {
                        break  // §6.1: octets after close_notify are ignored
                    }
                }
            }
            try maintainKeyUpdates()
        }
        catch {
            throw fail(error)
        }
        return events
    }

    /// The full-synchronous dispatch twin of `handle(_:into:)`.
    private mutating func handleFullSynchronous(
        _ event: TLSRecordEvent, into events: inout [TLSServerEvent]
    ) throws(TLSHandshakeError) {
        switch event {
            case .handshake(let fragment):
                coalescer.feed(fragment)
                while let message = try coalescer.next() {
                    try processFullSynchronous(message, into: &events)
                    if state.isTerminal {
                        return
                    }
                }
            case .applicationData, .alert:
                try handleNonHandshake(event, into: &events)
        }
    }

    /// The §A.2 gate with the two async arms replaced by their synchronous twins; every
    /// other (state, type) pair falls through to the shared synchronous arms.
    private mutating func processFullSynchronous(
        _ message: TLSHandshakeCoalescer.Message, into events: inout [TLSServerEvent]
    ) throws(TLSHandshakeError) {
        switch (state, message.type) {
            case (.expectingClientHello, .clientHello),
                (.expectingRetriedClientHello, .clientHello):
                try processClientHelloSynchronously(message)
            case (.expectingClientCertificate, .certificate):
                try processClientCertificateSynchronously(message)
            default:
                try processSynchronous(message, into: &events)
        }
    }

    /// The ClientHello arm without suspension: shared admission, shared flight construction,
    /// the §4.4.3 signature through ``TLSSynchronousIdentityProvider`` — or fail closed.
    private mutating func processClientHelloSynchronously(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) {
        guard let admitted = try examineClientHello(message) else {
            return  // the single permitted HelloRetryRequest went out instead
        }
        var pending = try prepareHandshakeFlight(
            admitted.hello,
            message: message,
            suite: admitted.suite,
            group: admitted.group,
            clientShare: admitted.share
        )
        let signature = try signatureSynchronouslyIfNeeded(pending.signing)
        try finishHandshakeFlight(&pending, signature: signature)
    }

    /// The synchronous half of the identity seam: signs through the refinement, or fails
    /// closed on a provider that only offers the async surface.
    private func signatureSynchronouslyIfNeeded(
        _ signing: PendingSignature?
    ) throws(TLSHandshakeError) -> TLSSignature? {
        guard let signing else {
            return nil
        }
        guard let provider = signing.identity as? any TLSSynchronousIdentityProvider else {
            throw .internalError("the identity provider cannot sign on the synchronous drive")
        }
        do {
            return try provider.signatureSynchronously(
                over: signing.content, algorithms: signing.candidates
            )
        }
        catch {
            throw .signingFailed
        }
    }

    /// The client-Certificate arm without suspension: shared intake, then the trust seam
    /// through ``TLSSynchronousClientChainValidator`` — or fail closed (never validate less).
    private mutating func processClientCertificateSynchronously(
        _ message: TLSHandshakeCoalescer.Message
    ) throws(TLSHandshakeError) {
        guard let chain = try admitClientCertificate(message) else {
            return  // empty chain, allowed by mode — no CertificateVerify follows
        }
        if let validator = configuration.clientChainValidator {
            guard let synchronous = validator as? any TLSSynchronousClientChainValidator
            else {
                throw .internalError(
                    "the client-chain validator cannot judge on the synchronous drive"
                )
            }
            switch synchronous.validateSynchronously(chainDER: chain) {
                case .accepted:
                    break
                case .rejected(let rejection):
                    throw .clientChainRejected(rejection)
            }
        }
        state = .expectingClientCertificateVerify
    }
}
