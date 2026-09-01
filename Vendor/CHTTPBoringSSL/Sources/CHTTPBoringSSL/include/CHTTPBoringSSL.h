//
//  CHTTPBoringSSL.h — vendored BoringSSL umbrella header
//
//  This module is a vendored, symbol-prefixed (CHTTPBoringSSL_*) copy of BoringSSL, providing the
//  libssl/libcrypto surface the portable TLS backbone needs (ADR 0004, Phase 6) with no system-OpenSSL
//  dependency. The C sources under crypto/, ssl/, gen/, third_party/ are BoringSSL (see LICENSE in each).
//  The vendoring layout + symbol-prefixing derive from swift-nio-ssl's process (Apache-2.0) — see NOTICE.txt
//  and hash.txt for the exact upstream revision. Do not edit by hand; re-run scripts/vendor-boringssl.sh.
//
#ifndef C_HTTP_BORINGSSL_H
#define C_HTTP_BORINGSSL_H

#include "CHTTPBoringSSL_aead.h"
#include "CHTTPBoringSSL_aes.h"
#include "CHTTPBoringSSL_arm_arch.h"
#include "CHTTPBoringSSL_asm_base.h"
#include "CHTTPBoringSSL_asn1_mac.h"
#include "CHTTPBoringSSL_asn1t.h"
#include "CHTTPBoringSSL_base.h"
#include "CHTTPBoringSSL_bio.h"
#include "CHTTPBoringSSL_blake2.h"
#include "CHTTPBoringSSL_blowfish.h"
#include "CHTTPBoringSSL_bn.h"
#include "CHTTPBoringSSL_boringssl_prefix_symbols.h"
#include "CHTTPBoringSSL_boringssl_prefix_symbols_asm.h"
#include "CHTTPBoringSSL_cast.h"
#include "CHTTPBoringSSL_chacha.h"
#include "CHTTPBoringSSL_ctrdrbg.h"
#include "CHTTPBoringSSL_cmac.h"
#include "CHTTPBoringSSL_conf.h"
#include "CHTTPBoringSSL_cpu.h"
#include "CHTTPBoringSSL_curve25519.h"
#include "CHTTPBoringSSL_des.h"
#include "CHTTPBoringSSL_dtls1.h"
#include "CHTTPBoringSSL_e_os2.h"
#include "CHTTPBoringSSL_ec.h"
#include "CHTTPBoringSSL_ec_key.h"
#include "CHTTPBoringSSL_ecdsa.h"
#include "CHTTPBoringSSL_err.h"
#include "CHTTPBoringSSL_evp.h"
#include "CHTTPBoringSSL_hkdf.h"
#include "CHTTPBoringSSL_hmac.h"
#include "CHTTPBoringSSL_hpke.h"
#include "CHTTPBoringSSL_hrss.h"
#include "CHTTPBoringSSL_kdf.h"
#include "CHTTPBoringSSL_md4.h"
#include "CHTTPBoringSSL_md5.h"
#include "CHTTPBoringSSL_mldsa.h"
#include "CHTTPBoringSSL_mlkem.h"
#include "CHTTPBoringSSL_obj_mac.h"
#include "CHTTPBoringSSL_objects.h"
#include "CHTTPBoringSSL_opensslv.h"
#include "CHTTPBoringSSL_ossl_typ.h"
#include "CHTTPBoringSSL_pkcs12.h"
#include "CHTTPBoringSSL_poly1305.h"
#include "CHTTPBoringSSL_rand.h"
#include "CHTTPBoringSSL_rc4.h"
#include "CHTTPBoringSSL_ripemd.h"
#include "CHTTPBoringSSL_rsa.h"
#include "CHTTPBoringSSL_safestack.h"
#include "CHTTPBoringSSL_service_indicator.h"
#include "CHTTPBoringSSL_sha.h"
#include "CHTTPBoringSSL_siphash.h"
#include "CHTTPBoringSSL_slhdsa.h"
#include "CHTTPBoringSSL_srtp.h"
#include "CHTTPBoringSSL_ssl.h"
#include "CHTTPBoringSSL_time.h"
#include "CHTTPBoringSSL_trust_token.h"
#include "CHTTPBoringSSL_type_check.h"
#include "CHTTPBoringSSL_x509_vfy.h"
#include "CHTTPBoringSSL_x509v3.h"
#include "experimental/CHTTPBoringSSL_kyber.h"

#endif  // C_HTTP_BORINGSSL_H
