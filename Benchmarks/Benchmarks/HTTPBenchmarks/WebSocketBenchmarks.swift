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

    // §5.2 — a large (4 KiB) masked frame: the 16-bit extended-length path + the per-byte unmask
    // loop at realistic message scale.
    Benchmark("websocket/FrameDecoder/decode-large") { benchmark in
        let wire = maskedBinaryFrame(payload: webSocketLargePayload)
        let decoder = WebSocketFrameDecoder()
        for _ in benchmark.scaledIterations {
            wire.withUnsafeBytes { raw in
                var reader = ByteReader(raw)
                blackHole(try? decoder.nextFrame(&reader))
            }
        }
    }

    // §5/§6 — the sans-I/O connection engine: a masked binary frame in → a reassembled message event
    // out (frame decode, unmask, single-fragment reassembly).
    Benchmark("websocket/Connection/receive") { benchmark in
        let wire = maskedBinaryFrame(payload: webSocketPayload)
        for _ in benchmark.scaledIterations {
            var connection = WebSocketConnection()
            blackHole(try? connection.receive(wire))
        }
    }

    // §5.4 — a fragmented message: an opening binary frame + two continuations (last FIN), all
    // masked → one reassembled message event (the fragment-accumulation path).
    Benchmark("websocket/Connection/receive-fragmented") { benchmark in
        let wire = maskedFragmentedMessage(parts: [
            Array("the quick brown ".utf8),
            Array("fox jumps over ".utf8),
            Array("the lazy dog".utf8),
        ])
        for _ in benchmark.scaledIterations {
            var connection = WebSocketConnection()
            blackHole(try? connection.receive(wire))
        }
    }

    // §8.1 — a text message: the engine validates the payload is well-formed UTF-8. This is the path
    // measured to decide whether to replace the allocating String round-trip with a scalar validator.
    Benchmark("websocket/Connection/receive-text") { benchmark in
        let wire = maskedBinaryFrame(opcode: 0x01, payload: webSocketTextPayload)
        for _ in benchmark.scaledIterations {
            var connection = WebSocketConnection()
            blackHole(try? connection.receive(wire))
        }
    }
}

/// A masked client→server binary frame carrying `payload` (RFC 6455 §5.2 / §5.3), with the length in
/// the minimal 7/16/64-bit form so any size round-trips.
private func maskedBinaryFrame(opcode: UInt8 = 0x02, payload: [UInt8]) -> [UInt8] {
    let key: [UInt8] = [0x37, 0xFA, 0x21, 0x3D]
    var wire: [UInt8] = [0x80 | opcode]  // FIN + opcode
    let count = payload.count
    if count <= 125 {
        wire.append(0x80 | UInt8(count))  // MASK bit + inline 7-bit length
    } else if count <= 0xFFFF {
        wire.append(0x80 | 126)  // MASK bit + 16-bit length marker
        wire.append(UInt8(truncatingIfNeeded: count >> 8))
        wire.append(UInt8(truncatingIfNeeded: count))
    } else {
        wire.append(0x80 | 127)  // MASK bit + 64-bit length marker
        for shift in stride(from: 56, through: 0, by: -8) {
            wire.append(UInt8(truncatingIfNeeded: count >> shift))
        }
    }
    wire.append(contentsOf: key)
    for (index, byte) in payload.enumerated() { wire.append(byte ^ key[index & 3]) }
    return wire
}

/// A masked, multi-fragment binary message (RFC 6455 §5.4).
///
/// An opening binary frame (FIN=0) then continuation frames, the last with FIN=1; each `part` is
/// assumed ≤ 125 octets.
private func maskedFragmentedMessage(parts: [[UInt8]]) -> [UInt8] {
    let key: [UInt8] = [0x37, 0xFA, 0x21, 0x3D]
    var wire = [UInt8]()
    for (index, part) in parts.enumerated() {
        let isFinal = index == parts.count - 1
        let opcode: UInt8 = index == 0 ? 0x02 : 0x00  // binary, then continuation
        wire.append((isFinal ? 0x80 : 0x00) | opcode)  // FIN bit + opcode
        wire.append(0x80 | UInt8(part.count))  // MASK bit + inline 7-bit length
        wire.append(contentsOf: key)
        for (byteIndex, byte) in part.enumerated() { wire.append(byte ^ key[byteIndex & 3]) }
    }
    return wire
}
