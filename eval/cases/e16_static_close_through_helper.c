// level: expert
// mode: static
// expect: double-close
// what: a helper closes the log; the error path closes the stream again (heap corruption in glibc)
#include <stdio.h>

static int finish_log(FILE *f) {
    int rc = fflush(f);
    fclose(f);
    return rc;
}

int write_report(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (!f)
        return -1;
    fputs(text, f);
    if (finish_log(f) != 0) {
        fclose(f); // finish_log already closed it
        return -1;
    }
    return 0;
}
