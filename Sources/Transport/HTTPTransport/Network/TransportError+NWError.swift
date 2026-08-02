//
//  TransportError+NWError.swift
//  HTTPTransport
//
//  Classifies the `NWError` a Network.framework listener reports so a bind that can never succeed
//  fails closed instead of waiting forever.
//
//  A listener that cannot claim its configured local endpoint does NOT always report `.failed`.
//  Measured on macOS 27 with `NWParameters.requiredLocalEndpoint` set:
//
//    • an address no interface owns (RFC 5737 192.0.2.1) → `.waiting(POSIX EADDRNOTAVAIL)`, forever;
//    • a port another listener holds                     → `.failed(POSIX EADDRINUSE)`.
//
//  So `.waiting` cannot simply be ignored — that is precisely the "does not fail closed" half of audit
//  F-05, and waiting forever on a misconfigured bind is a silent-startup failure (CWE-755: improper
//  handling of exceptional conditions). Nor can `.waiting` be treated as fatal wholesale: it is also
//  the normal state for a transient path condition, which a listener recovers from on its own. Only
//  the errors below are unrecoverable *for a bind*, so only they end the wait.
//
//  Standards: the POSIX.1-2017 `bind(2)` error set (`EADDRINUSE`, `EADDRNOTAVAIL`, `EACCES`, `EPERM`,
//  `EAFNOSUPPORT`, `EINVAL`).
//

internal import Darwin
internal import Network

extension TransportError {
    /// The fail-closed bind error `error` represents, or `nil` when a listener may still recover.
    ///
    /// `context` names what was being bound (the resolved endpoint), so an operator reading the log
    /// sees which address was refused rather than a bare `errno`.
    static func bindFailure(from error: NWError, binding context: String) -> TransportError? {
        guard case .posix(let code) = error, isUnrecoverableBindError(code) else {
            return nil
        }
        return .bindFailed("cannot bind \(context): \(error)")
    }

    /// Whether a POSIX code reported by a listener means the bind can never succeed as configured.
    private static func isUnrecoverableBindError(_ code: POSIXErrorCode) -> Bool {
        switch code {
            case .EADDRINUSE, .EADDRNOTAVAIL, .EACCES, .EPERM, .EAFNOSUPPORT, .EINVAL:
                true
            default:
                false
        }
    }
}
