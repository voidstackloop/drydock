// level: hard
// mode: static
// expect: weak-crypto
// what: a password is hashed with MD5, which can be searched and collided
unsigned char *MD5(const void *d, unsigned long n, unsigned char *md);

void digest(const void *p, unsigned long n, unsigned char *out) {
    MD5(p, n, out);
}
