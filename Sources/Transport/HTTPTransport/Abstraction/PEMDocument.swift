//
//  PEMDocument.swift
//  HTTPTransport
//
//  RFC 7468 textual PEM decoding for the transport layer's identity intake: splits a PEM text into
//  its `-----BEGIN <label>-----` … `-----END <label>-----` blocks and base64-decodes each body to
//  DER. Strict-enough parsing (RFC 7468 §3 "strict" grammar, minus line-length pedantry): matched
//  labels, standard base64 (RFC 4648 §4) via the shared codec, anything outside a block ignored
//  (headers/comments around blocks are explicitly allowed by §5.2). Runs at configuration time only.
//

internal import HTTPCore

/// One decoded PEM block (RFC 7468): its label and the DER bytes its base64 body encodes.
struct PEMDocument {
    /// The block's label — e.g. `"CERTIFICATE"`, `"PRIVATE KEY"`, `"EC PRIVATE KEY"`.
    let label: String

    /// The decoded DER contents.
    let der: [UInt8]

    /// Parses every well-formed PEM block in `text`, in order; malformed or unmatched blocks are
    /// skipped (the caller decides whether "no blocks" is an error).
    static func parse(_ text: String) -> [Self] {
        var documents: [Self] = []
        var label: String?
        var body = ""
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = trimmed(rawLine)
            if let opened = marker(line, prefix: "-----BEGIN ") {
                label = opened
                body = ""
                continue
            }
            if let closed = marker(line, prefix: "-----END ") {
                if let openLabel = label, openLabel == closed,
                    let der = Base64.decode(body, alphabet: .standard, padded: true)
                {
                    documents.append(Self(label: openLabel, der: der))
                }
                label = nil
                continue
            }
            if label != nil {
                body.append(contentsOf: line)
            }
        }
        return documents
    }

    /// The label of a `-----BEGIN/END <label>-----` marker line, or `nil` for any other line.
    private static func marker(_ line: Substring, prefix: String) -> String? {
        guard line.hasPrefix(prefix), line.hasSuffix("-----") else {
            return nil
        }
        return String(line.dropFirst(prefix.count).dropLast(5))
    }

    /// `line` with ASCII whitespace (space, tab, CR) trimmed from both ends — PEM lines may carry a
    /// trailing CR from CRLF files (RFC 7468 §2 permits either line ending).
    private static func trimmed(_ line: Substring) -> Substring {
        var slice = line
        while let first = slice.first, first == " " || first == "\t" || first == "\r" {
            slice = slice.dropFirst()
        }
        while let last = slice.last, last == " " || last == "\t" || last == "\r" {
            slice = slice.dropLast()
        }
        return slice
    }
}
