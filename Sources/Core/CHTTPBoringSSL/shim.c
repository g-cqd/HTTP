//
//  shim.c
//  CHTTPBoringSSL
//
//  Definitions of the libssl wrapper functions declared in CHTTPBoringSSL.h. The macro-based OpenSSL
//  configuration APIs and the STACK_OF(X509) helpers are macros, natural in C and invisible to the
//  Swift importer — so they live here, behind plain functions Swift can call. See ADR 0004.
//

#include <pthread.h>
#include <openssl/provider.h>

#include "CHTTPBoringSSL.h"

// OpenSSL 3 moved the SHA1-MAC / 3DES algorithms a PKCS#12 commonly uses (and which DevTLSIdentity's
// `-legacy` export — required for `SecPKCS12Import` — produces) into the non-default *legacy*
// provider. Load it once (alongside the default, which an explicit load would otherwise displace) so
// `PKCS12_parse` accepts both modern and legacy bundles. OpenSSL-specific; a vendored-BoringSSL
// provider (ADR 0004 phase 6) has no provider concept and omits this.
static void CHTTPBoringSSL_load_providers(void) {
    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "legacy");
}

long CHTTPBoringSSL_set_min_proto_version(SSL_CTX *ctx, int version) {
    return SSL_CTX_set_min_proto_version(ctx, version);
}

long CHTTPBoringSSL_set_max_proto_version(SSL_CTX *ctx, int version) {
    return SSL_CTX_set_max_proto_version(ctx, version);
}

int CHTTPBoringSSL_use_pkcs12(
    SSL_CTX *ctx, const uint8_t *bytes, int length, const char *passphrase) {
    static pthread_once_t providers = PTHREAD_ONCE_INIT;
    pthread_once(&providers, CHTTPBoringSSL_load_providers);
    BIO *source = BIO_new_mem_buf(bytes, length);
    if (source == NULL) {
        return 0;
    }
    PKCS12 *bundle = d2i_PKCS12_bio(source, NULL);
    BIO_free(source);
    if (bundle == NULL) {
        return 0;
    }
    EVP_PKEY *key = NULL;
    X509 *certificate = NULL;
    STACK_OF(X509) *chain = NULL;
    int parsed = PKCS12_parse(bundle, passphrase, &key, &certificate, &chain);
    PKCS12_free(bundle);
    if (parsed != 1 || certificate == NULL || key == NULL) {
        if (key != NULL) EVP_PKEY_free(key);
        if (certificate != NULL) X509_free(certificate);
        if (chain != NULL) sk_X509_pop_free(chain, X509_free);
        return 0;
    }
    int ok = SSL_CTX_use_certificate(ctx, certificate) == 1
        && SSL_CTX_use_PrivateKey(ctx, key) == 1;
    if (ok && chain != NULL) {
        for (int i = 0; i < sk_X509_num(chain); i++) {
            // add1 takes its own reference, so the stack is freed below regardless.
            SSL_CTX_add1_chain_cert(ctx, sk_X509_value(chain, i));
        }
    }
    EVP_PKEY_free(key);
    X509_free(certificate);
    if (chain != NULL) {
        sk_X509_pop_free(chain, X509_free);
    }
    return ok;
}

// Server ALPN preference, wire-format (RFC 7301): length-prefixed "h2", then "http/1.1".
static const unsigned char http_alpn_preferences[] = {
    2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'
};

static int http_alpn_select(
    SSL *ssl, const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl;
    (void)arg;
    // Pick our highest preference present in the client's list; no overlap fails the handshake
    // (ALPACA hardening, RFC 7301 §3.2) rather than silently serving an unnegotiated protocol.
    if (SSL_select_next_proto(
            (unsigned char **)out, outlen, http_alpn_preferences,
            (unsigned int)sizeof(http_alpn_preferences), in, inlen) == OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

void CHTTPBoringSSL_set_alpn_select_h2(SSL_CTX *ctx) {
    SSL_CTX_set_alpn_select_cb(ctx, http_alpn_select, NULL);
}

int CHTTPBoringSSL_set_client_alpn(SSL_CTX *ctx) {
    static const unsigned char protocols[] = { 2, 'h', '2' };
    return SSL_CTX_set_alpn_protos(ctx, protocols, (unsigned int)sizeof(protocols));
}

// Drains all pending ciphertext from one memory BIO into another (peer direction).
static void transfer(BIO *from, BIO *to) {
    char buffer[16384];
    int read;
    while ((read = BIO_read(from, buffer, (int)sizeof(buffer))) > 0) {
        BIO_write(to, buffer, read);
    }
}

int CHTTPBoringSSL_handshake(SSL *server, SSL *client) {
    // Bounded ping-pong: the client (connect) speaks first; each side's output is fed to the other's
    // input until both report a finished handshake. 200 rounds is far beyond TLS 1.3's flights.
    for (int round = 0; round < 200; round++) {
        SSL_do_handshake(client);
        transfer(SSL_get_wbio(client), SSL_get_rbio(server));
        SSL_do_handshake(server);
        transfer(SSL_get_wbio(server), SSL_get_rbio(client));
        if (SSL_is_init_finished(server) && SSL_is_init_finished(client)) {
            return 1;
        }
    }
    return 0;
}
