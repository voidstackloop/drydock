// level: hard
// mode: static
// expect: command-injection
// what: argv is handed to a function in another file that runs a shell on it
// with: parts/h73_shell.c
void shellify(const char *what);

int main(int argc, char **argv) {
    if (argc > 1)
        shellify(argv[1]);
    return 0;
}
