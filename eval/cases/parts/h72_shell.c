// The other file of h72: it does run whatever it is given, and the caller is
// what decides that it is only ever "date".
#include <stdlib.h>

void run(const char *line) { system(line); }
