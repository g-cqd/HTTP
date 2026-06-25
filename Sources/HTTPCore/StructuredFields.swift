//
//  StructuredFields.swift
//  HTTPCore
//
//  RFC 8941 Structured Field Values — the typed data model. A growing set of HTTP headers (RFC 9218
//  `Priority`, `Accept-CH`, `Cache-Status`, `Proxy-Status`, …) are defined as Structured Fields rather
//  than ad-hoc grammars, so a server that parses them needs one rigorous, fail-closed parser instead
//  of a bespoke one per header. This namespace holds the model; `StructuredFields+Parsing.swift` is the
//  parser (the security-relevant direction — untrusted request header values).
//
//  Parsing is iterative and bounded (no recursion: an inner list nests exactly one level, parsed
//  inline), and never traps — malformed input is a typed ``StructuredFields/ParseError``.
//

/// RFC 8941 Structured Field Values: the model plus (in `+Parsing`) a fail-closed parser.
public enum StructuredFields {
    /// A bare item — the leaf value of the grammar (RFC 8941 §3.3), before any parameters.
    public enum BareItem: Sendable, Equatable {
        /// An integer in the range ±(10¹⁵ − 1) (§3.3.1).
        case integer(Int64)
        /// A decimal with at most 12 integer and 3 fractional digits (§3.3.2).
        case decimal(Double)
        /// A string of printable ASCII (§3.3.3).
        case string(String)
        /// A token — an HTTP token-like symbol (§3.3.4).
        case token(String)
        /// A byte sequence, carried base64 on the wire (§3.3.5).
        case byteSequence([UInt8])
        /// A boolean (§3.3.6).
        case boolean(Bool)
    }

    /// One parameter: a key bound to a bare item (a bare key defaults to boolean `true`) (§3.1.2).
    public struct Parameter: Sendable, Equatable {
        /// The parameter key (lowercase-leading; see RFC 8941 §3.1.2 key grammar).
        public let key: String
        /// The parameter value.
        public let value: BareItem

        /// Creates a parameter binding `key` to `value`.
        public init(key: String, value: BareItem) {
            self.key = key
            self.value = value
        }
    }

    /// An ordered map of parameters (§3.1.2): insertion order is preserved and a duplicate key keeps
    /// its original position while taking the later value.
    public struct Parameters: Sendable, Equatable {
        /// The parameters in order.
        public private(set) var entries: [Parameter]

        /// Creates a parameter set (empty by default).
        public init(_ entries: [Parameter] = []) {
            self.entries = entries
        }

        /// The value bound to `key`, or `nil` if absent.
        public subscript(_ key: String) -> BareItem? {
            entries.first { $0.key == key }?.value
        }

        /// Binds `key` to `value`, overwriting in place if the key already exists (RFC 8941 §4.2.3.2).
        public mutating func set(_ key: String, to value: BareItem) {
            if let index = entries.firstIndex(where: { $0.key == key }) {
                entries[index] = Parameter(key: key, value: value)
            }
            else {
                entries.append(Parameter(key: key, value: value))
            }
        }
    }

    /// An item: a bare item with its parameters (§3.3).
    public struct Item: Sendable, Equatable {
        /// The bare value.
        public var bareItem: BareItem
        /// The item's parameters.
        public var parameters: Parameters

        /// Creates an item from a bare value and optional parameters.
        public init(_ bareItem: BareItem, parameters: Parameters = Parameters()) {
            self.bareItem = bareItem
            self.parameters = parameters
        }
    }

    /// An inner list: an ordered list of items, plus the inner list's own parameters (§3.1.1).
    public struct InnerList: Sendable, Equatable {
        /// The member items.
        public var items: [Item]
        /// The inner list's parameters.
        public var parameters: Parameters

        /// Creates an inner list from its items and optional parameters.
        public init(_ items: [Item], parameters: Parameters = Parameters()) {
            self.items = items
            self.parameters = parameters
        }
    }

    /// A member of a list or a dictionary value: either a single item or an inner list (§3.1).
    public enum Member: Sendable, Equatable {
        /// A single item member.
        case item(Item)
        /// An inner-list member.
        case innerList(InnerList)
    }

    /// One dictionary entry: a key bound to a member (§3.2).
    public struct DictionaryEntry: Sendable, Equatable {
        /// The entry key.
        public let key: String
        /// The entry value.
        public let value: Member

        /// Creates a dictionary entry binding `key` to `value`.
        public init(key: String, value: Member) {
            self.key = key
            self.value = value
        }
    }

    /// Why parsing a Structured Field value failed (RFC 8941 §4.2) — always fail-closed, never a trap.
    public enum ParseError: Error, Sendable, Equatable {
        /// The field value was empty (or only whitespace) where a value was required.
        case empty
        /// Characters remained after a complete value was parsed (§4.2 step 7).
        case trailingCharacters
        /// Input ended while a value was still expected.
        case unexpectedEndOfInput
        /// No valid bare-item began here (§4.2.3.1).
        case invalidBareItem
        /// An integer exceeded the ±(10¹⁵ − 1) range / digit cap (§4.2.4).
        case integerOutOfRange
        /// A decimal was malformed — a trailing dot, too many fractional/integer digits (§4.2.4).
        case invalidDecimal
        /// A string had no closing quote (§4.2.5).
        case unterminatedString
        /// A string contained a non-printable / non-ASCII octet (§4.2.5).
        case invalidStringCharacter
        /// A string escape was not `\"` or `\\` (§4.2.5).
        case invalidEscapeSequence
        /// A byte sequence had no closing colon (§4.2.7).
        case unterminatedByteSequence
        /// A byte sequence was not valid base64 (§4.2.7).
        case invalidByteSequence
        /// A boolean was not `?0` or `?1` (§4.2.8).
        case invalidBoolean
        /// A key did not match the key grammar (§4.2.3.3).
        case invalidKey
        /// A list/dictionary member was not followed by a comma separator (§4.2.1 / §4.2.2).
        case expectedComma
        /// A list/dictionary ended on a trailing comma (§4.2.1 / §4.2.2).
        case trailingComma
        /// An inner-list item was not delimited by a space or closing paren (§4.2.1.2).
        case invalidInnerList
    }
}
