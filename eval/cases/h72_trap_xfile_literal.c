// level: hard
// mode: static
// expect: none
// what: a function in another file runs a shell on its parameter, but the one call passes a literal
// with: parts/h72_shell.c
void run(const char *line);

int main(void) {
    run("date");
    return 0;
}
