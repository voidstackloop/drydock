// level: basic
// mode: dynamic
// expect: none
// what: trap: allocation, file and mutex all used correctly
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

int main(void) {
    char *s = strdup("text");
    FILE *f = fopen("/etc/hostname", "r");
    if (f) {
        char line[128];
        fgets(line, sizeof line, f);
        fclose(f);
    }
    pthread_mutex_lock(&mu);
    s[0] = 'T';
    pthread_mutex_unlock(&mu);
    free(s);
    return 0;
}
