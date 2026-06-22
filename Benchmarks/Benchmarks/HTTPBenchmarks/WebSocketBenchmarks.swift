//
//  WebSocketBenchmarks.swift
//  HTTPBenchmarks
//
//  RFC 6455 §5.2 / §5.3 — the WebSocket frame codec: decoding a masked client→server frame (header
//  parse, payload-length resolution, in-place unmask) and encoding a server→client frame.
//

import Benchmark
import HTTPCore
import WebSocket

func registerWebSocketBenchmarks() {
    // §5.2/§5.3 — the server-receive hot path: parse the header, resolve the length, and unmask.
    Benchmark("websocket/FrameDecoder/decode-masked") { benchmark in
        let wire = maskedBinaryFrame(payload: webSocketPayload)
        let decoder = WebSocketFrameDecoder()
        for _ in benchmark.scaledIterations {
            wire.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(try? decoder.nextFrame(&reader))
            }
        }
    }

    // §5.2 — the server-send path: a single-allocation header + payload, unmasked.
    Benchmark("websocket/FrameEncoder/encode") { benchmark in
        let encoder = WebSocketFrameEncoder()
        let frame = WebSocketFrame(opcode: .binary, payload: webSocketPayload)
        for _ in benchmark.scaledIterations {
            blackHole(encoder.encode(frame))
        }
    }
}

/// A masked client→server binary frame carrying `payload` (RFC 6455 §5.2 / §5.3; `payload` ≤ 125 so
/// the inline 7-bit length form applies).
private func maskedBinaryFrame(payload: [UInt8]) -> [UInt8] {
    let key: [UInt8] = [0x37, 0xFA, 0x21, 0x3D]
    var wire: [UInt8] = [0x82, 0x80 | UInt8(payload.count)]  // FIN+binary; MASK bit + 7-bit length
    wire.append(contentsOf: key)
    for (index, byte) in payload.enumerated() { wire.append(byte ^ key[index & 3]) }
    return wire
}
