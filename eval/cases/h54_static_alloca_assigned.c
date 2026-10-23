// level: hard
// mode: static
// expect: unbounded-alloca
// what: the size is parsed from an argument into a variable, then given to alloca()
int main(int argc, char **argv) {
    size_t n = strtoul(argv[1], 0, 10);
    char *p = alloca(n);
    (void)p;
    return 0;
}
