//
//  CHTTPBoringSSL.h
//  CHTTPBoringSSL
//
//  The single C surface over libssl for the portable (non-Network.framework) TLS backbone
//  (ADR 0004). It is the *only* place that #includes <openssl/...>; the Swift `OpenSSLProvider`
//  imports this module and never touches the raw headers. Linked against system OpenSSL today
//  (gated behind HTTP_PORTABLE_TLS); a vendored BoringSSL provider drops in behind the same module
//  later. BoringSSL is API-compatible for this surface.
//
//  Most of OpenSSL's configuration entry points are *macros* (e.g. SSL_CTX_set_min_proto_version
//  expands to SSL_CTX_ctrl(...)), which the Swift importer cannot call. This header therefore
//  declares small wrapper *functions* (defined in shim.c) for the macro-based APIs the provider
//  needs, keeping the unsafe macro/stack interop in auditable C — the same discipline
//  NetworkFrameworkTLS applies to the sec_protocol_* surface.
//
//  Standards: TLS 1.3 (RFC 8446); ALPN (RFC 7301); PKCS#12 (RFC 7292).
//

#ifndef CHTTPBORINGSSL_H
#define CHTTPBORINGSSL_H

#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/// Pins the minimum negotiated TLS protocol version (e.g. TLS1_3_VERSION). Returns 1 on success.
///
/// Wraps the `SSL_CTX_set_min_proto_version` macro (RFC 8446 / RFC 9325 floor).
long CHTTPBoringSSL_set_min_proto_version(SSL_CTX *ctx, int version);

/// Pins the maximum negotiated TLS protocol version. Returns 1 on success.
///
/// Wraps the `SSL_CTX_set_max_proto_version` macro (audit T-F5: pin the ceiling too).
long CHTTPBoringSSL_set_max_proto_version(SSL_CTX *ctx, int version);

/// Loads a PKCS#12 (RFC 7292) blob — the same `TransportTLS.pkcs12` bytes the Network backbone uses —
/// into `ctx` as the server certificate, private key, and chain. Returns 1 on success, 0 on any
/// failure. No keychain is touched (the portability win over `SecPKCS12Import`).
int CHTTPBoringSSL_use_pkcs12(
    SSL_CTX *ctx, const uint8_t *bytes, int length, const char *passphrase);

/// Installs a server-side ALPN (RFC 7301) selection callback preferring `h2`, then `http/1.1`, and
/// failing the handshake on no overlap (the strict-ALPN / ALPACA posture, RFC 7301 §3.2).
void CHTTPBoringSSL_set_alpn_select_h2(SSL_CTX *ctx);

/// Advertises `h2` as the client's offered ALPN protocol (test/interop helper). Returns 0 on success
/// (note OpenSSL's inverted convention for this one call).
int CHTTPBoringSSL_set_client_alpn(SSL_CTX *ctx);

/// Drives a TLS handshake to completion between two memory-BIO-backed `SSL` objects in-process,
/// pumping ciphertext between their BIOs — the deterministic, socket-free form of the memory-BIO
/// bridge the production connection will use (ADR 0004). `server` must be in accept state and
/// `client` in connect state, each with a read and write `BIO_s_mem`. Returns 1 once both complete,
/// 0 if it fails to converge.
int CHTTPBoringSSL_handshake(SSL *server, SSL *client);

/// Opens a blocking TCP connection to `127.0.0.1:port` and returns the descriptor, or `-1` on failure
/// — a test-only helper so a libssl client can drive the transport's accept loop without the POSIX
/// `sockaddr` plumbing leaking into Swift.
int CHTTPBoringSSL_connect_loopback(uint16_t port);

/// Configures client-certificate authentication (mTLS, RFC 8446 §4.4.2) on `ctx`: `mode` 0 = none (no
/// CertificateRequest), 1 = optional (`SSL_VERIFY_PEER` — request, but proceed if the client presents
/// none), 2 = required (`+ SSL_VERIFY_FAIL_IF_NO_PEER_CERT` — the handshake fails without a cert).
///
/// A *presented* certificate is accepted at the TLS layer (default trust evaluation is replaced), so
/// the actual trust decision is the caller's post-handshake `verifyPeer` hook over the DER chain — the
/// G3 "the verify hook is the policy; a `nil` hook accepts any presented chain" semantics, ported.
void CHTTPBoringSSL_set_client_auth(SSL_CTX *ctx, int mode);

/// Writes the peer leaf certificate's Common Name into `buffer` (NUL-terminated), returning its length,
/// or `-1` when no client certificate was presented (or it carries no CN). The leaf-subject identity
/// surfaced as `TransportConnection.tlsPeerSubject`.
int CHTTPBoringSSL_peer_subject(SSL *ssl, char *buffer, int buffer_length);

/// Invokes `emit(der, length, context)` once per peer certificate, **leaf-first** — each a DER-encoded
/// (RFC 5280) buffer valid for the call's duration only. The backbone-agnostic chain the `verifyPeer`
/// trust hook consumes. (Server-side libssl keeps the leaf separate from the chain, so the leaf is
/// emitted explicitly, then the rest of the chain, de-duplicated.)
void CHTTPBoringSSL_peer_der_chain(
    SSL *ssl, void (*emit)(const uint8_t *der, int length, void *context), void *context);

#endif
