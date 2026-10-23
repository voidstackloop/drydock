// level: expert
// mode: static
// expect: unbounded-alloca
// what: a helper allocates a stack buffer of the length of the text it was given, and main passes it an argument
void copy_in(const char *s) {
    char *p = alloca(strlen(s) + 1);
    (void)p;
}

int main(int argc, char **argv) {
    copy_in(argv[1]);
    return 0;
}
