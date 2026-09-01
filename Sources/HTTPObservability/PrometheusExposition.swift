//
//  PrometheusExposition.swift
//  HTTPObservability
//
//  The Prometheus text exposition format, version 0.0.4 — the stable text format served as
//  `text/plain; version=0.0.4`. This is the one place the format's lexical rules live: the
//  `# HELP` / `# TYPE` comment lines, label-value escaping (backslash, double quote, line feed),
//  help-text escaping (backslash, line feed), the canonical non-finite renderings `NaN` / `+Inf` /
//  `-Inf`, and name sanitization to the spec's character sets (metric names `[a-zA-Z0-9_:]`, label
//  names `[a-zA-Z0-9_]`, neither starting with a digit; every invalid character becomes `_`).
//
//  Reference: Prometheus "Exposition formats" (text format version 0.0.4).
//

/// The lexical rules of the Prometheus text exposition format 0.0.4.
enum PrometheusExposition {
    /// Writes the `# HELP` (only when `help` is non-empty) and `# TYPE` lines for one metric family.
    static func writeHeader(name: String, type: String, help: String, into buffer: inout [UInt8]) {
        if !help.isEmpty {
            buffer.append(contentsOf: "# HELP ".utf8)
            buffer.append(contentsOf: name.utf8)
            buffer.append(UInt8(ascii: " "))
            appendEscapedHelp(help, to: &buffer)
            buffer.append(UInt8(ascii: "\n"))
        }
        buffer.append(contentsOf: "# TYPE ".utf8)
        buffer.append(contentsOf: name.utf8)
        buffer.append(UInt8(ascii: " "))
        buffer.append(contentsOf: type.utf8)
        buffer.append(UInt8(ascii: "\n"))
    }

    /// The prerendered `name{label="value",…} ` (or `name ` when unlabeled) prefix of a sample line.
    static func renderedSamplePrefix(name: String, labels: [(String, String)]) -> [UInt8] {
        var prefix: [UInt8] = []
        prefix.reserveCapacity(name.utf8.count + 24)
        prefix.append(contentsOf: name.utf8)
        if labels.isEmpty {
            prefix.append(UInt8(ascii: " "))
        }
        else {
            prefix.append(UInt8(ascii: "{"))
            prefix.append(contentsOf: renderedLabels(labels))
            prefix.append(contentsOf: "} ".utf8)
        }
        return prefix
    }

    /// The `label="value",…` byte run (no braces), label values escaped per the spec.
    static func renderedLabels(_ labels: [(String, String)]) -> [UInt8] {
        var rendered: [UInt8] = []
        for (index, label) in labels.enumerated() {
            if index > 0 {
                rendered.append(UInt8(ascii: ","))
            }
            rendered.append(contentsOf: label.0.utf8)
            rendered.append(contentsOf: "=\"".utf8)
            appendEscapedLabelValue(label.1, to: &rendered)
            rendered.append(UInt8(ascii: "\""))
        }
        return rendered
    }

    /// Writes a floating-point sample value: canonical `NaN` / `+Inf` / `-Inf`, else the shortest
    /// round-trippable decimal (`Double.description`).
    static func writeDouble(_ value: Double, into buffer: inout [UInt8]) {
        if value.isNaN {
            buffer.append(contentsOf: "NaN".utf8)
        }
        else if value == .infinity {
            buffer.append(contentsOf: "+Inf".utf8)
        }
        else if value == -.infinity {
            buffer.append(contentsOf: "-Inf".utf8)
        }
        else {
            buffer.append(contentsOf: value.description.utf8)
        }
    }

    /// Writes a non-negative duration as decimal seconds, exactly.
    ///
    /// `Duration` is fixed-point (seconds + attoseconds), so this renders the exact value with
    /// trailing zeros trimmed and always at least one fractional digit (`1.0`, `0.005`) — the same
    /// shape swift-prometheus produced, so dashboards keyed on `le` values keep matching.
    static func writeSeconds(of duration: Duration, into buffer: inout [UInt8]) {
        let components = duration.components
        buffer.append(contentsOf: String(components.seconds).utf8)
        buffer.append(UInt8(ascii: "."))
        // 18 attosecond digits, most significant first, then trim trailing zeros (keep >= 1 digit).
        var digits: [UInt8] = Array(repeating: UInt8(ascii: "0"), count: 18)
        var remaining = components.attoseconds
        var index = 17
        while remaining > 0 {
            digits[index] = UInt8(ascii: "0") + UInt8(remaining % 10)
            remaining /= 10
            index -= 1
        }
        var length = 18
        while length > 1, digits[length - 1] == UInt8(ascii: "0") {
            length -= 1
        }
        buffer.append(contentsOf: digits[0 ..< length])
    }

    /// The metric name with every character outside `[a-zA-Z0-9_:]` (or a leading digit) replaced
    /// by `_`.
    static func sanitizedMetricName(_ name: String) -> String {
        sanitizedName(name, allowingColon: true)
    }

    /// The labels with every label NAME sanitized to `[a-zA-Z0-9_]`; values pass through (they are
    /// escaped at render time instead).
    static func sanitizedLabels(_ labels: [(String, String)]) -> [(String, String)] {
        labels.map { (sanitizedName($0.0, allowingColon: false), $0.1) }
    }

    // MARK: - Escaping

    /// Escapes a label value per the spec: `\` → `\\`, `"` → `\"`, line feed → `\n`.
    private static func appendEscapedLabelValue(_ value: String, to buffer: inout [UInt8]) {
        for byte in value.utf8 {
            switch byte {
                case UInt8(ascii: "\\"):
                    buffer.append(contentsOf: "\\\\".utf8)
                case UInt8(ascii: "\""):
                    buffer.append(contentsOf: "\\\"".utf8)
                case UInt8(ascii: "\n"):
                    buffer.append(contentsOf: "\\n".utf8)
                default:
                    buffer.append(byte)
            }
        }
    }

    /// Escapes help text per the spec: `\` → `\\`, line feed → `\n` (quotes are legal in help).
    private static func appendEscapedHelp(_ help: String, to buffer: inout [UInt8]) {
        for byte in help.utf8 {
            switch byte {
                case UInt8(ascii: "\\"):
                    buffer.append(contentsOf: "\\\\".utf8)
                case UInt8(ascii: "\n"):
                    buffer.append(contentsOf: "\\n".utf8)
                default:
                    buffer.append(byte)
            }
        }
    }

    // MARK: - Name sanitization

    private static func sanitizedName(_ name: String, allowingColon: Bool) -> String {
        var sanitized = ""
        sanitized.reserveCapacity(name.utf8.count)
        var isFirst = true
        for byte in name.utf8 {
            let valid = isValidNameByte(byte, first: isFirst, allowingColon: allowingColon)
            // Every kept byte is ASCII by construction, so the scalar append cannot mis-decode.
            sanitized.append(valid ? Character(UnicodeScalar(byte)) : "_")
            isFirst = false
        }
        return sanitized.isEmpty ? "_" : sanitized
    }

    private static func isValidNameByte(_ byte: UInt8, first: Bool, allowingColon: Bool) -> Bool {
        switch byte {
            case UInt8(ascii: "A") ... UInt8(ascii: "Z"), UInt8(ascii: "a") ... UInt8(ascii: "z"):
                true
            case UInt8(ascii: "_"):
                true
            case UInt8(ascii: ":"):
                allowingColon
            case UInt8(ascii: "0") ... UInt8(ascii: "9"):
                !first
            default:
                false
        }
    }
}
