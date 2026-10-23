// level: expert
// mode: static
// expect: unchecked-stream
// what: a plugin scan checks one directory's open but not the fallback directory's
#include <dirent.h>
#include <stdio.h>
#include <string.h>

static int count_plugins(DIR *d) {
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        n += strstr(e->d_name, ".so") != NULL;
    return n;
}

int scan(const char *dir, const char *fallback) {
    DIR *d = opendir(dir);
    if (d) {
        int n = count_plugins(d);
        closedir(d);
        if (n)
            return n;
    }
    d = opendir(fallback); // not checked this time
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL)
        n += strstr(e->d_name, ".so") != NULL;
    closedir(d);
    return n;
}
