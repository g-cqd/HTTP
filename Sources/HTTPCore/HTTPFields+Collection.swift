//
//  HTTPFields+Collection.swift
//  HTTPCore
//
//  RFC 9110 §5 — `RandomAccessCollection` conformance over the ordered field storage, preserving the
//  on-the-wire order §5.3 makes significant for repeated field names.
//

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
