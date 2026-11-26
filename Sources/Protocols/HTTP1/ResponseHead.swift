//
//  ResponseHead.swift
//  HTTP1
//
//  RFC 9112 §4 / §5 / §6.3 — a parsed HTTP/1.x response head (status-line + header section, no body).
//

public import HTTPCore

/// A parsed HTTP/1.x response head: the response message (status + fields), the status-line
/// version (RFC 9112 §2.3), and how its body is delimited on the wire (RFC 9112 §6.3).
public typealias ResponseHead = (
    response: HTTPResponse, version: HTTPVersion, framing: ResponseBodyFraming
)
