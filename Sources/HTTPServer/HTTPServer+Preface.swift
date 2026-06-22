//
//  HTTPServer+Preface.swift
//  HTTPServer
//
//  HTTP/2 cleartext (h2c, "prior knowledge") preface detection (RFC 9113 §3.4): the connection sniffer
//  matches the distinctive 16-octet client preface marker ("PRI * HTTP/2.0\r\n") that no HTTP/1.1
//  request line can begin with, committing the connection to HTTP/2 once it is seen.
//

internal import HTTP2

extension HTTPServer {

    /// The length of the HTTP/2 client preface marker that, once matched, commits to HTTP/2.
    static var http2MarkerLength: Int { 16 }

    /// Whether `buffer` is a prefix of the HTTP/2 client preface (so the connection may still be h2).
    static func couldBeHTTP2Preface(_ buffer: [UInt8]) -> Bool {
        let marker = HTTP2ConnectionPreface.client
        for index in 0..<min(buffer.count, marker.count) where buffer[index] != marker[index] {
            return false
        }
        return true
    }

    /// Whether the first 16 octets of `buffer` are the HTTP/2 preface marker (the commit point to h2).
    static func matchesHTTP2Marker(_ buffer: [UInt8]) -> Bool {
        let marker = HTTP2ConnectionPreface.client
        guard buffer.count >= http2MarkerLength else { return false }
        for index in 0..<http2MarkerLength where buffer[index] != marker[index] { return false }
        return true
    }
}
