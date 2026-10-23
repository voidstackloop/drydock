// The other file of e75: a parameter of run_tool() is passed on to run_after(),
// which runs a shell on it. Nothing in this file passes text from outside, so
// only the caller in the other file can say whether the shell is reachable.
#include <stdlib.h>

void run_after(const char *line);

void run_tool(const char *arg) { run_after(arg); }

void run_after(const char *line) { system(line); }
