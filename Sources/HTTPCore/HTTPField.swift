//
//  HTTPField.swift
//  HTTPCore
//
//  RFC 9110 §5 — a single header (or trailer) field: a name paired with a value.
//

/// A single HTTP field — a ``HTTPFieldName`` paired with a value (RFC 9110 §5).
///
/// Construction validates the value against the `field-value` grammar (RFC 9110 §5.5), so an
/// `HTTPField` can never carry a value containing CR, LF, or NUL — the bytes that enable header
/// injection / response splitting.
public struct HTTPField: Sendable, Hashable {

    /// The field name (case-insensitive).
    public let name: HTTPFieldName

    /// The field value — guaranteed to satisfy the RFC 9110 §5.5 `field-value` grammar.
    public let value: String

    /// Creates a field, returning `nil` if `value` is not a legal `field-value`.
    public init?(name: HTTPFieldName, value: String) {
        guard FieldValidation.isValidFieldValue(value.utf8) else { return nil }
        self.name = name
        self.value = value
    }

    /// Creates a field from a string name, returning `nil` if the name is not a valid `token` or
    /// the value is not a legal `field-value`.
    public init?(name: String, value: String) {
        guard let fieldName = HTTPFieldName(name) else { return nil }
        self.init(name: fieldName, value: value)
    }

    /// Creates a field whose value is already known to be legal (used by trusted internal paths).
    @usableFromInline
    init(uncheckedName name: HTTPFieldName, value: String) {
        self.name = name
        self.value = value
    }
}
