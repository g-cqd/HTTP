//
//  HTTPPriority.swift
//  HTTPCore
//
//  RFC 9218 Extensible Prioritization — the `Priority` header, parsed from / serialized to an RFC 8941
//  Structured Field Dictionary. This is the first consumer of the Structured Fields codec, turning a
//  raw header value into a typed urgency / incremental pair (and back), so the codec is wired to a real
//  feature rather than standing alone.
//

/// An RFC 9218 client priority signal: a stream urgency and an incremental-delivery preference.
public struct HTTPPriority: Sendable, Equatable {
    /// The default urgency, applied when the field or its `u` member is absent (RFC 9218 §4.1).
    public static let defaultUrgency = 3

    /// Urgency from 0 (most urgent) to 7 (least urgent); default 3.
    public var urgency: Int

    /// Whether the response may be delivered incrementally; default `false`.
    public var incremental: Bool

    /// Creates a priority from an urgency and incremental flag.
    public init(urgency: Int = Self.defaultUrgency, incremental: Bool = false) {
        self.urgency = urgency
        self.incremental = incremental
    }

    /// Parses an RFC 9218 `Priority` field value.
    ///
    /// An unparseable field — or a member that is missing, out of range, or the wrong type — falls back
    /// to the default; parsing a priority never fails (RFC 9218 §4.1: unrecognized input is ignored).
    public init(field value: String) {
        var urgency = Self.defaultUrgency
        var incremental = false
        if let entries = try? StructuredFields.parseDictionary(value) {
            for entry in entries {
                guard case .item(let item) = entry.value else {
                    continue
                }
                if entry.key == "u", case .integer(let raw) = item.bareItem, raw >= 0, raw <= 7 {
                    urgency = Int(raw)
                }
                else if entry.key == "i", case .boolean(let flag) = item.bareItem {
                    incremental = flag
                }
            }
        }
        self.init(urgency: urgency, incremental: incremental)
    }

    /// The canonical `Priority` field value, omitting any member equal to its default (RFC 9218 §4);
    /// an all-default priority serializes to the empty string.
    public var fieldValue: String {
        var entries: [StructuredFields.DictionaryEntry] = []
        if urgency != Self.defaultUrgency {
            entries.append(
                StructuredFields.DictionaryEntry(
                    key: "u",
                    value: .item(StructuredFields.Item(.integer(Int64(urgency))))
                )
            )
        }
        if incremental {
            entries.append(
                StructuredFields.DictionaryEntry(
                    key: "i",
                    value: .item(StructuredFields.Item(.boolean(true)))
                )
            )
        }
        return (try? StructuredFields.serialize(dictionary: entries)) ?? ""
    }
}

extension HTTPRequest {
    /// The request's RFC 9218 ``HTTPPriority``, or `nil` when no `Priority` field is present.
    public var priority: HTTPPriority? {
        guard let value = headerFields[.priority] else {
            return nil
        }
        return HTTPPriority(field: value)
    }
}
