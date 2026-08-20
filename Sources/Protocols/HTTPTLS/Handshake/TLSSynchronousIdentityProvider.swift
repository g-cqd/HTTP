//
//  TLSSynchronousIdentityProvider.swift
//  HTTPTLS
//
//  The synchronous refinement of the identity seam (Phase 3d): a provider whose §4.4.3
//  signing completes without suspension. ``TLSIdentityProvider`` is async so hardware- or
//  remote-backed signers fit; every LOCAL signer this package ships is synchronous under
//  that surface (``TLSIdentitySigner`` is "synchronous by design"), and the portable TLS
//  backbone's engine adapter drives the whole handshake under a `Mutex` — a context that
//  cannot suspend. This refinement is how such a driver asks for the signature without
//  blocking a cooperative thread: providers that can, conform; the synchronous drive
//  (``TLSServerConnection/receiveSynchronously(_:)``) fails closed (`internal_error`) on
//  providers that cannot, rather than degrading to a hidden wait.
//

/// A ``TLSIdentityProvider`` whose signing completes without suspension (RFC 8446 §4.4.3).
public protocol TLSSynchronousIdentityProvider: TLSIdentityProvider {
    /// Signs the §4.4.3 content under the first workable scheme from `algorithms` — the
    /// ``TLSIdentityProvider/signature(over:algorithms:)`` contract, without suspension.
    func signatureSynchronously(
        over content: [UInt8], algorithms: [TLSSignatureScheme]
    ) throws -> TLSSignature
}
