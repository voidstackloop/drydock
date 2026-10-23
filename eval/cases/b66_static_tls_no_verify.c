// level: basic
// mode: static
// expect: tls-no-verify
// what: the TLS context verifies nothing (SSL_VERIFY_NONE), so a man in the middle is the server
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, void *callback);
void SSL_set_verify(SSL *ssl, int mode, void *callback);
#define SSL_VERIFY_NONE 0
#define SSL_VERIFY_PEER 1

int main(void) {
    SSL_CTX *ctx = 0;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
    return 0;
}
