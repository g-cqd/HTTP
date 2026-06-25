//
//  ExpectDispositionTests.swift
//  HTTPServerTests
//
//  RFC 9110 §10.1.1 — the `Expect: 100-continue` classifier: when to send an interim 100, when to
//  proceed, and when to answer 417.
//

import HTTP1
import HTTPCore
import Testing

@testable import HTTPServer

@Suite("Expect: 100-continue (RFC 9110 §10.1.1)")
struct ExpectDispositionTests {
    private func head(
        expect: String?,
        framing: BodyFraming,
        version: HTTPVersion = .http11
    ) -> RequestHead {
        var fields = HTTPFields()
        if let expect {
            _ = fields.append(expect, for: .expect)
        }
        let request = HTTPRequest(
            method: .post, scheme: "https", authority: "x", path: "/", headerFields: fields
        )
        return RequestHead(request: request, version: version, framing: framing)
    }

    @Test("no Expect field → proceed")
    func noExpect() {
        #expect(
            ExpectDisposition.evaluate(head(expect: nil, framing: .contentLength(5))) == .proceed)
    }

    @Test("100-continue with a body on HTTP/1.1 → send the interim 100")
    func continueWithBody() {
        #expect(
            ExpectDisposition.evaluate(head(expect: "100-continue", framing: .contentLength(5)))
                == .sendContinue)
        #expect(
            ExpectDisposition.evaluate(head(expect: "100-continue", framing: .chunked))
                == .sendContinue)
    }

    @Test("100-continue with no body → proceed (the interim is moot)")
    func continueNoBody() {
        #expect(
            ExpectDisposition.evaluate(head(expect: "100-continue", framing: .none)) == .proceed)
        #expect(
            ExpectDisposition.evaluate(head(expect: "100-continue", framing: .contentLength(0)))
                == .proceed)
    }

    @Test("100-continue on HTTP/1.0 → proceed (1.0 does not use it)")
    func continueHTTP10() {
        #expect(
            ExpectDisposition.evaluate(
                head(expect: "100-continue", framing: .contentLength(5), version: .http10)
            ) == .proceed)
    }

    @Test(
        "an unsupported expectation → 417",
        arguments: ["bogus", "100-continue, bogus", "200-ok"])
    func unsupported(_ value: String) {
        #expect(
            ExpectDisposition.evaluate(head(expect: value, framing: .contentLength(5))) == .failed)
    }

    @Test("case and surrounding whitespace are tolerated on 100-continue")
    func caseAndWhitespace() {
        #expect(
            ExpectDisposition.evaluate(head(expect: " 100-Continue ", framing: .contentLength(5)))
                == .sendContinue)
    }
}
