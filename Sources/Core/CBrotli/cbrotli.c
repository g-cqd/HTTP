//
//  cbrotli.c
//  CBrotli
//
//  RFC 7932 `br` content coding over libbrotli (one-shot encode + decode). Each wrapper funnels
//  libbrotli's `BROTLI_BOOL` / `BrotliDecoderResult` to "octets written, or 0 on failure" so the Swift
//  side reads 0 as "could not encode/decode" (mirroring CZstd / CZlibCoding). No state is held across
//  calls; the caller owns the buffers.
//

#include "CBrotli.h"

// Compiled to an EMPTY translation unit unless the `Brotli` package trait is enabled: the trait drives
// a `.define("HTTP_TRAIT_BROTLI", .when(traits: ["Brotli"]))` cSetting in the manifest. The target is
// always declared (an SE-0450 trait cannot conditionally declare one), so this #ifdef is what keeps a
// default build from referencing the <brotli/*.h> headers — which need not even be installed. Replaces
// the retired `HTTP_BROTLI` env-var gate.
#ifdef HTTP_TRAIT_BROTLI

#include <brotli/decode.h>
#include <brotli/encode.h>

size_t cbrotli_compress_bound(size_t src_size) {
    return BrotliEncoderMaxCompressedSize(src_size);  // 0 ⇒ input too large for a single-pass bound
}

size_t cbrotli_compress(
    uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len, int quality
) {
    size_t encoded_size = dst_cap;  // in: capacity; out: octets written
    BROTLI_BOOL ok = BrotliEncoderCompress(
        quality, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_GENERIC, src_len, src, &encoded_size, dst
    );
    return ok == BROTLI_TRUE ? encoded_size : 0;  // dst too small / bad quality / error: fail closed
}

size_t cbrotli_decompress(uint8_t *dst, size_t dst_cap, const uint8_t *src, size_t src_len) {
    size_t decoded_size = dst_cap;  // in: capacity; out: octets written
    BrotliDecoderResult result = BrotliDecoderDecompress(src_len, src, &decoded_size, dst);
    // SUCCESS only when the whole stream decoded into dst; NEEDS_MORE_OUTPUT (dst too small ⇒ a bomb past
    // the cap) and ERROR both fail closed.
    return result == BROTLI_DECODER_RESULT_SUCCESS ? decoded_size : 0;
}

#endif /* HTTP_TRAIT_BROTLI */
