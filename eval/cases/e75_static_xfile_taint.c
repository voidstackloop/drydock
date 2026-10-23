// level: expert
// mode: static
// expect: command-injection
// what: text from the environment is passed across two files into system(), and reaches it through a second function there
// with: parts/e75_tool.c
#include <stdio.h>
#include <stdlib.h>

void run_tool(const char *arg);

int main(int argc, char **argv) {
    if (argc > 1)
        run_tool(getenv(argv[1]));
    return 0;
}
