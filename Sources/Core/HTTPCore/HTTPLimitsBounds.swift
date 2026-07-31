//
//  HTTPLimitsBounds.swift
//  HTTPCore
//
//  The legal range of every knob in `HTTPLimits`, in one table (2026-07-31 audit, CR-F15).
//
//  It is a table rather than a run of inline `min`/`max` calls so the clamping initializer and the
//  throwing one read the *same* definition. Before this, the invariants were documented on the type
//  and enforced — inconsistently — by whichever consumer happened to care: `WebSocketBroadcastMailbox`
//  did a defensive `max(1, capacity)`, `ConnectionAdmission` clamped the resume ratio,
//  `RateLimitMiddleware` clamped its own limit, and `acceptResumeRatio`'s own doc comment claimed a
//  clamp that lived two modules away. Each consumer re-guessed, and nothing made them agree.
//

extension HTTPLimits {
    /// The enforced range of every limit, with the standard that fixes it.
    ///
    /// Ranges are open at the top (`Int.max`) wherever no standard fixes a ceiling: the point is to
    /// exclude the values that are *incoherent* — a zero frame size, a negative body cap, a
    /// non-positive timeout — not to second-guess an operator who has measured their deployment.
    enum Bounds {
        /// A request line has at least one octet (RFC 9112 §3).
        static let requestLine = 1 ... Int.max

        /// A field is at least a one-octet name (RFC 9110 §5.1).
        static let fieldSize = 1 ... Int.max

        /// Zero is legal: it refuses every header section (RFC 9113 §6.5.2).
        static let headerList = 0 ... Int.max

        /// HTTP/1.1 requires `Host`, so a message carries at least one field (RFC 9112 §3.2).
        static let fieldCount = 1 ... Int.max

        /// Zero is legal: it refuses every request that carries content (RFC 9110 §8.6).
        static let bodySize = 0 ... Int.max

        /// Zero is legal: it refuses every non-empty WebSocket message (RFC 6455 §5.4).
        static let webSocketMessage = 0 ... Int.max

        /// Zero is legal: it refuses every compressed body outright (CWE-409).
        static let decompressedBody = 0 ... Int.max

        /// A ratio below 1 would refuse output no larger than its input — incoherent (CWE-409).
        static let decompressionRatio = 1 ... Int.max

        /// `Content-Encoding` with no decodable layer is not a coding list (RFC 9110 §8.4.1).
        static let decompressionLayers = 1 ... Int.max

        /// Zero concurrent streams deadlocks the connection; RFC 9113 §5.1.2 recommends at least 100.
        static let streams = 1 ... Int.max

        /// The frame-size window RFC 9113 §4.2 fixes at 2^14 … 2^24-1.
        ///
        /// A `SETTINGS_MAX_FRAME_SIZE` outside it is a `PROTOCOL_ERROR`, and the floor is the one
        /// range in this table an engine cannot survive violating — a zero frames nothing and spins.
        static let frame = 16_384 ... 16_777_215

        /// Zero is legal and meaningful: it disables the dynamic table (RFC 7541 §4.2).
        static let headerTable = 0 ... Int.max

        /// A header block that may carry no CONTINUATION cannot express a large field set
        /// (RFC 9113 §6.10, CVE-2024-27316).
        static let continuations = 1 ... Int.max

        /// A budget of zero would `GOAWAY` on the first reset any client is entitled to send
        /// (RFC 9113 §6.4, CVE-2023-44487).
        static let resets = 1 ... Int.max

        /// A budget of zero would `GOAWAY` on the first legal SETTINGS acknowledgement
        /// (RFC 9113 §6.5.3, CVE-2019-9513).
        static let control = 1 ... Int.max

        /// A zero-octet watermark parks the reader before it has read anything — a deadlock, not
        /// backpressure (2026-07-31 audit, F1/F3).
        static let queuedBytes = 1 ... Int.max

        /// A zero-chunk watermark parks the reader before it has read anything, as above.
        static let queuedChunks = 1 ... Int.max

        /// A queue that holds nothing drops every broadcast and closes every subscriber with `1008`
        /// (RFC 6455 §7.4.1).
        static let queuedBroadcasts = 1 ... Int.max

        /// The flow-control window RFC 9113 §6.9.1 caps at 2^31-1.
        ///
        /// The engine advertises the stream half in `SETTINGS_INITIAL_WINDOW_SIZE`, so a larger value
        /// could not be expressed on the wire; zero would stall every stream permanently.
        static let window = 1 ... 2_147_483_647

        /// A window of zero can frame no chunk and would deadlock the decoder (RFC 9112 §7.1).
        static let bodyWindow = 1 ... Int.max

        /// Zero is legal: it releases the read buffer after every request (CWE-401).
        static let keepAliveBuffer = 0 ... Int.max

        /// A ceiling of zero admits nothing — a server that refuses every connection (audit T-F2).
        static let connections = 1 ... Int.max

        /// The hysteresis fraction (audit F8). `1` re-arms on the first free slot; `0` re-arms only
        /// once the server has fully drained.
        static let ratio = 0.0 ... 1.0

        /// The floor every timeout, interval, and deadline is held at.
        ///
        /// A non-positive duration expires before the work it bounds can start, which turns a
        /// Slowloris defense into a guarantee that no request ever completes. One nanosecond is the
        /// nearest legal value, and the one a clamping caller gets; a caller that would rather be
        /// told uses ``HTTPLimits/init(validating:)``.
        static let minimumDuration = Duration.nanoseconds(1)

        /// The hysteresis fraction substituted for a ratio that is not a number.
        ///
        /// NaN is unordered, so there is nothing to clamp it *to*, and `Int(Double.nan)` traps
        /// downstream (IEEE 754-2019 §7.2; see `ConnectionAdmission`). The documented default is the
        /// only substitution that preserves the property the field was configured for.
        static let defaultRatio = 0.875

        /// `duration`, floored at ``minimumDuration``.
        static func positive(_ duration: Duration) -> Duration {
            max(duration, minimumDuration)
        }

        /// `value` clamped into ``ratio``, NaN-safely.
        ///
        /// `Double.minimum`/`Double.maximum` are the IEEE 754 operations that return the *non*-NaN
        /// operand; the `Comparable` `min`/`max` return NaN from both, because every ordered
        /// comparison against NaN is false. ±∞ therefore clamps correctly here, and only a true NaN
        /// reaches ``defaultRatio``.
        static func clamping(_ value: Double) -> Double {
            let defined = value.isNaN ? defaultRatio : value
            return Double.minimum(Double.maximum(defined, ratio.lowerBound), ratio.upperBound)
        }
    }
}

extension ClosedRange<Int> {
    /// `value` pinned into this range.
    ///
    /// `Swift.min`/`Swift.max` explicitly: inside an extension on `ClosedRange`, the bare names
    /// resolve to the `Sequence` methods this type gains by conditional conformance.
    func clamping(_ value: Bound) -> Bound {
        Swift.min(Swift.max(value, lowerBound), upperBound)
    }
}
