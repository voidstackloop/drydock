// level: basic
// mode: static
// expect: unbounded-alloca
// what: alloca() of one past the length of an argument, which the caller can make as long as it likes
int main(int argc, char **argv) {
    char *p = alloca(strlen(argv[1]) + 1);
    (void)p;
    return 0;
}
