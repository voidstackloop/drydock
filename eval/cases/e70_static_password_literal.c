// level: expert
// mode: static
// expect: hardcoded-secret
// what: a login check compares the password with the literal letmein, which anyone who reads the program knows
#include <string.h>

int grant(void);

int check(const char *password) {
    if (strcmp(password, "letmein") == 0)
        return grant();
    return 0;
}
