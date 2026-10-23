// level: basic
// mode: static
// expect: none
// what: trap: verification is on (SSL_VERIFY_PEER), and a 0 constant without the name is not SSL_VERIFY_NONE
typedef struct ssl_ctx_st SSL_CTX;
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, void *callback);
#define SSL_VERIFY_PEER 1

int main(void) {
    SSL_CTX *ctx = 0;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, 0);
    return 0;
}
