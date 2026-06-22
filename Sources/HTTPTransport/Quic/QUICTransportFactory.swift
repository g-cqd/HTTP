//
//  QUICTransportFactory.swift
//  HTTPTransport
//
//  The single QUIC-backbone selection point — the one place an `#available(macOS 26, iOS 26, *)` gate
//  lives (the codebase otherwise has none; this establishes the pattern). Two backbones implement
//  ``QUICServerTransport``:
//
//    • ``LegacyQUICTransport`` — the `NWConnectionGroup` callback API available at the macOS 15 floor.
//      It is also exercised on macOS 26, so it provides working HTTP/3 across the whole support range.
//    • The modern `NetworkConnection<QUIC>` typed-channel API (macOS 26+) is the native path; it slots
//      into the `#available` branch below once its channel send/receive surface is wired and validated.
//
//  Keeping the gate here means every other file stays availability-free and floors at `macOS(.v15)`.
//

public import HTTPCore

/// Creates the ``QUICServerTransport`` backbone appropriate to the running OS (RFC 9114 over QUIC).
public enum QUICTransportFactory {

    /// The QUIC backbone for `configuration`, chosen by OS version.
    ///
    /// On macOS 26+ / iOS 26+ this is where the modern `NetworkConnection<QUIC>` backbone is selected;
    /// the legacy `NWConnectionGroup` backbone (which also runs on macOS 26) is used otherwise and as
    /// the validated default across the support range.
    public static func make(
        _ configuration: TransportConfiguration,
        limits: HTTPLimits = .default
    ) -> any QUICServerTransport {
        if #available(macOS 26, iOS 26, *) {
            // The modern NetworkConnection<QUIC> backbone plugs in here; until its typed-channel API is
            // wired, the legacy backbone (verified on macOS 26) serves this branch too.
            return LegacyQUICTransport(configuration: configuration, limits: limits)
        }
        return LegacyQUICTransport(configuration: configuration, limits: limits)
    }
}
