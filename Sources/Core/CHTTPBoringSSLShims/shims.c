//
//  shim.c
//  CHTTPBoringSSLShims
//
//  Definitions of the libssl wrapper functions declared in CHTTPBoringSSLShims.h. The macro-based OpenSSL
//  configuration APIs and the STACK_OF(X509) helpers are macros, natural in C and invisible to the
//  Swift importer — so they live here, behind plain functions Swift can call. See ADR 0004.
//

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "CHTTPBoringSSLShims.h"  // pulls <openssl/ssl.h>, which defines OPENSSL_IS_BORINGSSL on BoringSSL

#ifndef OPENSSL_IS_BORINGSSL
#include <openssl/provider.h>

// OpenSSL 3 moved the SHA1-MAC / 3DES algorithms a PKCS#12 commonly uses (and which DevTLSIdentity's
// `-legacy` export — required for `SecPKCS12Import` — produces) into the non-default *legacy*
// provider. Load it once (alongside the default, which an explicit load would otherwise displace) so
// `PKCS12_parse` accepts both modern and legacy bundles. OpenSSL-specific; vendored BoringSSL (ADR
// 0004 phase 6) keeps these PBES1 ciphers built in (`kBuiltinPBE`) with no provider concept, so the
// whole load compiles out under `OPENSSL_IS_BORINGSSL`.
static void CHTTPBoringSSLShims_load_providers(void) {
    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "legacy");
}
#endif

#ifdef OPENSSL_IS_BORINGSSL
// BoringSSL never renamed the owning peer-certificate accessor: its `SSL_get_peer_certificate` already
// returns a +1 reference the caller frees — exactly OpenSSL 3's `SSL_get1_peer_certificate`. This is
// pure ABI drift (no behavioral difference); alias it so the shim body below reads identically on both.
#define SSL_get1_peer_certificate SSL_get_peer_certificate
#endif

long CHTTPBoringSSLShims_set_min_proto_version(SSL_CTX *ctx, int version) {
    return SSL_CTX_set_min_proto_version(ctx, version);
}

long CHTTPBoringSSLShims_set_max_proto_version(SSL_CTX *ctx, int version) {
    return SSL_CTX_set_max_proto_version(ctx, version);
}

int CHTTPBoringSSLShims_use_pkcs12(
    SSL_CTX *ctx, const uint8_t *bytes, int length, const char *passphrase) {
#ifndef OPENSSL_IS_BORINGSSL
    // OpenSSL needs the legacy provider for DevTLSIdentity's `-legacy` PKCS#12; BoringSSL parses it
    // natively (built-in PBES1), so the load is compiled out above and there is nothing to prime.
    static pthread_once_t providers = PTHREAD_ONCE_INIT;
    pthread_once(&providers, CHTTPBoringSSLShims_load_providers);
#endif
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

void CHTTPBoringSSLShims_set_alpn_select_h2(SSL_CTX *ctx) {
    SSL_CTX_set_alpn_select_cb(ctx, http_alpn_select, NULL);
}

int CHTTPBoringSSLShims_set_client_alpn(SSL_CTX *ctx) {
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

int CHTTPBoringSSLShims_handshake(SSL *server, SSL *client) {
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

int CHTTPBoringSSLShims_connect_loopback(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int permissive_verify(int preverify_ok, X509_STORE_CTX *store) {
    (void)preverify_ok;
    (void)store;
    // Accept any *presented* certificate at the TLS layer: the platform default trust evaluation
    // (which would reject a self-signed / privately-issued client cert) is replaced by the caller's
    // post-handshake verifyPeer hook over the DER chain (the G3 "verify hook is the policy" semantics).
    return 1;
}

void CHTTPBoringSSLShims_set_client_auth(SSL_CTX *ctx, int mode) {
    if (mode == 0) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        return;
    }
    int verify_mode = SSL_VERIFY_PEER;  // optional: request, proceed if absent
    if (mode == 2) {
        verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;  // required: fail without a cert
    }
    SSL_CTX_set_verify(ctx, verify_mode, permissive_verify);
}

int CHTTPBoringSSLShims_peer_subject(SSL *ssl, char *buffer, int buffer_length) {
    X509 *certificate = SSL_get1_peer_certificate(ssl);
    if (certificate == NULL) {
        return -1;
    }
    int length = X509_NAME_get_text_by_NID(
        X509_get_subject_name(certificate), NID_commonName, buffer, buffer_length);
    X509_free(certificate);
    return length;
}

static void emit_der(X509 *certificate, void (*emit)(const uint8_t *, int, void *), void *context) {
    unsigned char *der = NULL;
    int length = i2d_X509(certificate, &der);
    if (length >= 0) {
        emit(der, length, context);
        OPENSSL_free(der);
    }
}

void CHTTPBoringSSLShims_peer_der_chain(
    SSL *ssl, void (*emit)(const uint8_t *, int, void *), void *context) {
    // Server-side libssl returns the leaf separately from the chain, so emit the leaf first, then the
    // remaining chain (skipping a duplicated leaf), giving the caller a leaf-first DER chain.
    X509 *leaf = SSL_get1_peer_certificate(ssl);
    if (leaf != NULL) {
        emit_der(leaf, emit, context);
    }
    STACK_OF(X509) *chain = SSL_get_peer_cert_chain(ssl);
    if (chain != NULL) {
        int count = (int)sk_X509_num(chain);
        for (int i = 0; i < count; i++) {
            X509 *certificate = sk_X509_value(chain, i);
            if (leaf != NULL && X509_cmp(certificate, leaf) == 0) {
                continue;
            }
            emit_der(certificate, emit, context);
        }
    }
    if (leaf != NULL) {
        X509_free(leaf);
    }
}

// SNI multi-cert registry (RFC 6066 §3): a per-default-SSL_CTX name -> SSL_CTX map, attached via
// ex_data so the server-name callback can look up the matching context. The registry owns a reference
// to each context and frees the registry + its contexts when the default SSL_CTX is freed.
struct sni_entry {
    char *name;
    SSL_CTX *context;
};

struct sni_registry {
    struct sni_entry *entries;
    int count;
    int capacity;
};

static int sni_registry_index = -1;
static pthread_once_t sni_once = PTHREAD_ONCE_INIT;

static void sni_registry_free(
    void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp) {
    (void)parent;
    (void)ad;
    (void)idx;
    (void)argl;
    (void)argp;
    struct sni_registry *registry = ptr;
    if (registry == NULL) {
        return;
    }
    for (int i = 0; i < registry->count; i++) {
        free(registry->entries[i].name);
        SSL_CTX_free(registry->entries[i].context);
    }
    free(registry->entries);
    free(registry);
}

static void sni_init_index(void) {
    sni_registry_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, sni_registry_free);
}

static int sni_servername_cb(SSL *ssl, int *al, void *arg) {
    (void)al;
    (void)arg;
    const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (name == NULL) {
        return SSL_TLSEXT_ERR_OK;  // no SNI → keep the default context
    }
    struct sni_registry *registry = SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl), sni_registry_index);
    if (registry == NULL) {
        return SSL_TLSEXT_ERR_OK;
    }
    for (int i = 0; i < registry->count; i++) {
        if (strcmp(registry->entries[i].name, name) == 0) {
            SSL_set_SSL_CTX(ssl, registry->entries[i].context);
            return SSL_TLSEXT_ERR_OK;
        }
    }
    return SSL_TLSEXT_ERR_OK;  // unmatched name → keep the default context
}

void CHTTPBoringSSLShims_enable_sni(SSL_CTX *default_ctx) {
    pthread_once(&sni_once, sni_init_index);
    struct sni_registry *registry = calloc(1, sizeof(*registry));
    if (registry == NULL) {
        return;
    }
    SSL_CTX_set_ex_data(default_ctx, sni_registry_index, registry);
    SSL_CTX_set_tlsext_servername_callback(default_ctx, sni_servername_cb);
}

void CHTTPBoringSSLShims_add_sni_context(SSL_CTX *default_ctx, const char *name, SSL_CTX *per_name_ctx) {
    struct sni_registry *registry = SSL_CTX_get_ex_data(default_ctx, sni_registry_index);
    if (registry == NULL) {
        return;
    }
    if (registry->count == registry->capacity) {
        int capacity = registry->capacity == 0 ? 4 : registry->capacity * 2;
        struct sni_entry *entries = realloc(registry->entries, (size_t)capacity * sizeof(*entries));
        if (entries == NULL) {
            return;
        }
        registry->entries = entries;
        registry->capacity = capacity;
    }
    registry->entries[registry->count].name = strdup(name);
    SSL_CTX_up_ref(per_name_ctx);
    registry->entries[registry->count].context = per_name_ctx;
    registry->count++;
}

void CHTTPBoringSSLShims_set_sni(SSL *ssl, const char *name) {
    SSL_set_tlsext_host_name(ssl, name);
}

int CHTTPBoringSSLShims_use_pem(
    SSL_CTX *ctx,
    const uint8_t *certificate_pem, int certificate_length,
    const uint8_t *key_pem, int key_length) {
    // Chain: the leaf's CERTIFICATE block first (RFC 7468), issuer blocks after it (RFC 5280 order).
    BIO *certificates = BIO_new_mem_buf(certificate_pem, certificate_length);
    if (certificates == NULL) {
        return 0;
    }
    X509 *leaf = PEM_read_bio_X509(certificates, NULL, NULL, NULL);
    if (leaf == NULL) {
        BIO_free(certificates);
        return 0;
    }
    int loaded = SSL_CTX_use_certificate(ctx, leaf) == 1;
    X509_free(leaf);
    while (loaded) {
        X509 *link = PEM_read_bio_X509(certificates, NULL, NULL, NULL);
        if (link == NULL) {
            ERR_clear_error();  // end of the PEM text, not a failure
            break;
        }
        loaded = SSL_CTX_add1_chain_cert(ctx, link) == 1;
        X509_free(link);
    }
    BIO_free(certificates);
    if (!loaded) {
        return 0;
    }
    // Key: PKCS#8 "PRIVATE KEY" (RFC 5958), SEC1 "EC PRIVATE KEY" (RFC 5915), or PKCS#1
    // "RSA PRIVATE KEY" (RFC 8017) — PEM_read_bio_PrivateKey handles all three, unencrypted.
    BIO *key_source = BIO_new_mem_buf(key_pem, key_length);
    if (key_source == NULL) {
        return 0;
    }
    EVP_PKEY *key = PEM_read_bio_PrivateKey(key_source, NULL, NULL, NULL);
    BIO_free(key_source);
    if (key == NULL) {
        return 0;
    }
    int usable = SSL_CTX_use_PrivateKey(ctx, key) == 1 && SSL_CTX_check_private_key(ctx) == 1;
    EVP_PKEY_free(key);
    return usable;
}

void *CHTTPBoringSSLShims_trust_store_create(void) {
    return X509_STORE_new();
}

int CHTTPBoringSSLShims_trust_store_add_root(void *store, const uint8_t *der, int length) {
    const uint8_t *cursor = der;
    X509 *root = d2i_X509(NULL, &cursor, length);
    if (root == NULL) {
        return 0;
    }
    int added = X509_STORE_add_cert((X509_STORE *)store, root) == 1;
    X509_free(root);  // the store took its own reference
    return added;
}

void CHTTPBoringSSLShims_trust_store_free(void *store) {
    X509_STORE_free((X509_STORE *)store);
}

void *CHTTPBoringSSLShims_chain_create(void) {
    return sk_X509_new_null();
}

int CHTTPBoringSSLShims_chain_append(void *chain, const uint8_t *der, int length) {
    const uint8_t *cursor = der;
    X509 *certificate = d2i_X509(NULL, &cursor, length);
    if (certificate == NULL) {
        return 0;
    }
    if (sk_X509_push((STACK_OF(X509) *)chain, certificate) == 0) {
        X509_free(certificate);
        return 0;
    }
    return 1;  // the stack owns the reference; chain_free releases it
}

void CHTTPBoringSSLShims_chain_free(void *chain) {
    sk_X509_pop_free((STACK_OF(X509) *)chain, X509_free);
}

int CHTTPBoringSSLShims_trust_store_validate(void *store, void *chain) {
    STACK_OF(X509) *presented = (STACK_OF(X509) *)chain;
    X509 *leaf = sk_X509_value(presented, 0);
    if (leaf == NULL) {
        return 0;
    }
    X509_STORE_CTX *context = X509_STORE_CTX_new();
    if (context == NULL) {
        return 0;
    }
    // The whole presented stack rides as "untrusted" helpers; the leaf's own presence there is
    // harmless (path building starts from the explicit leaf) — RFC 5280 §6 via X509_verify_cert.
    int validated = 0;
    if (X509_STORE_CTX_init(context, (X509_STORE *)store, leaf, presented) == 1) {
        validated = X509_verify_cert(context) == 1;
    }
    X509_STORE_CTX_free(context);
    return validated;
}
