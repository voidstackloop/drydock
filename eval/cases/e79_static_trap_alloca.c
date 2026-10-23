// level: expert
// mode: static
// expect: none
// what: trap: alloca() of a constant, of sizeof a local buffer, of a local count, and of a parameter every caller passes as a constant
void pad(size_t n) {
    char *p = alloca(n);
    (void)p;
}

int main(void) {
    char buf[64];
    char *a = alloca(64);
    char *b = alloca(sizeof buf);
    int n = 32;
    char *c = alloca(n);
    pad(16);
    (void)a;
    (void)b;
    (void)c;
    return 0;
}
