//
//  HTTPFields.swift
//  HTTPCore
//
//  RFC 9110 §5 — an ordered collection of header (or trailer) fields.
//

/// An ordered collection of HTTP fields (RFC 9110 §5).
///
/// Backed by a single contiguous array rather than a hash map: header sections are small (typically
/// well under 32 fields), so an ordered array with linear lookup is more cache-friendly and
/// allocates less than a dictionary, while preserving the on-the-wire order that RFC 9110 §5.3
/// makes significant for repeated field names.
public struct HTTPFields: Sendable, Equatable {

    @usableFromInline
    var storage: [HTTPField]

    /// Creates an empty field collection.
    public init() {
        storage = []
    }

    /// Creates a field collection from an ordered list of fields.
    public init(_ fields: [HTTPField]) {
        storage = fields
    }

    /// The combined value of every field line named `name`, or `nil` if none are present.
    ///
    /// Per RFC 9110 §5.3, repeated field lines sharing a name are combined into one value by
    /// joining them in order, separated by `", "`. **Exception:** `Set-Cookie` must not be combined
    /// this way (RFC 9110 §5.3, RFC 6265 §5.2) — read it with ``values(for:)`` instead.
    public subscript(name: HTTPFieldName) -> String? {
        var combined: String?
        for field in storage where field.name == name {
            if combined == nil {
                combined = field.value  // single match (the common case): returned as-is, no copy
            } else {
                // Grow one buffer in place instead of building O(n²) intermediate concatenations.
                combined?.append(", ")
                combined?.append(field.value)
            }
        }
        return combined
    }

    /// Every value for `name`, in order, as separate strings (never combined).
    public func values(for name: HTTPFieldName) -> [String] {
        storage.compactMap { $0.name == name ? $0.value : nil }
    }

    /// Whether any field line named `name` is present.
    public func contains(_ name: HTTPFieldName) -> Bool {
        storage.contains { $0.name == name }
    }

    /// Appends a field line, preserving order and any existing lines of the same name.
    public mutating func append(_ field: HTTPField) {
        storage.append(field)
    }

    /// Appends a field line built from `value` and `name`.
    ///
    /// Returns `false` (leaving the collection unchanged) if `value` is not a legal `field-value`.
    @discardableResult
    public mutating func append(_ value: String, for name: HTTPFieldName) -> Bool {
        guard let field = HTTPField(name: name, value: value) else { return false }
        storage.append(field)
        return true
    }

    /// Replaces every field line named `name` with a single line carrying `value`.
    ///
    /// Returns `false` (leaving the collection unchanged) if `value` is not a legal `field-value`.
    /// A surviving replacement is placed at the position of the first removed line, else appended.
    @discardableResult
    public mutating func setValue(_ value: String, for name: HTTPFieldName) -> Bool {
        guard let field = HTTPField(name: name, value: value) else { return false }
        if let firstIndex = storage.firstIndex(where: { $0.name == name }) {
            storage.removeAll { $0.name == name }
            storage.insert(field, at: firstIndex)
        } else {
            storage.append(field)
        }
        return true
    }

    /// Removes every field line named `name`.
    public mutating func removeAll(named name: HTTPFieldName) {
        storage.removeAll { $0.name == name }
    }
}

extension HTTPFields: RandomAccessCollection {

    // `Element` (HTTPField) and `Index` (Int) are inferred from the members below.

    /// The position of the first field (RFC 9110 §5.3 order is preserved).
    public var startIndex: Int { storage.startIndex }

    /// The position one past the last field.
    public var endIndex: Int { storage.endIndex }

    /// The field at `position` in wire order.
    public subscript(position: Int) -> HTTPField { storage[position] }

    /// The position immediately after `index`.
    public func index(after index: Int) -> Int { storage.index(after: index) }

    /// The position immediately before `index`.
    public func index(before index: Int) -> Int { storage.index(before: index) }
}

extension HTTPFields {

    /// An empty field collection — a readable alias for `HTTPFields()`.
    public static var empty: HTTPFields { HTTPFields() }
}
