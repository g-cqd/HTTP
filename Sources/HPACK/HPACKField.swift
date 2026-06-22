//
//  HPACKField.swift
//  HPACK
//
//  RFC 7541 §1.3 — a header field as HPACK models it: a name/value pair of octet strings. The type is
//  shared with QPACK (RFC 9204), so it is hoisted into HTTPCore as ``HeaderField``; `HPACKField` is a
//  thin alias kept for source stability across the HPACK and HTTP/2 sources that name it.
//

public import HTTPCore

/// A header field name/value pair as represented inside HPACK (RFC 7541 §1.3) — an alias for the
/// shared ``HeaderField``.
public typealias HPACKField = HeaderField
