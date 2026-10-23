#pragma once
// Intraprocedural dataflow over one function: tracks heap objects per
// allocation site through pointer variables and reports misuse.
#include "parser.h"

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace lcstatic {

// One step of the route text from outside took to reach a dangerous call:
// where it entered, what carried it (a variable, a call), the call itself.
struct FlowStep {
    FlowStep() = default;
    FlowStep(std::string what, std::string function, int line, int col = 0,
             int param = -1)
        : what(std::move(what)), function(std::move(function)), line(line),
          col(col), param(param) {}

    std::string what;     // "argv", "cmd", "system()"
    std::string function; // where that step is
    int line = 0;
    int col = 0;
    int param = -1;   // when `what` is a parameter of `function`: which one
    std::string file; // empty: the file the finding is written in
};

struct Issue {
    std::string rule; // same ids as the dynamic engine (see reporter rules)
    std::string message;
    std::string function;
    int line = 0;
    int col = 0;
    int alloc_line = 0; // related locations, 0 if none
    int free_line = 0;
    std::vector<FlowStep> flow; // empty when there is no route to show
};

// `taken` was locked at `line` while `held` (locked at held_line) was
// certainly held. Mutexes as written: "g_mu", "s->mu". analyze_function
// also records the raw facts with_calls() turns into orders: a lock with
// nothing held (held empty), and a call made while holding `held` (taken
// empty, via = the function called).
struct LockOrder {
    std::string held, taken, function;
    int line = 0, held_line = 0;
    std::string file; // set when orders of several files are compared
    std::string via;  // taken inside this function of the file, called here
};

// The orders of a file's functions, with "holding A, calling g()" made
// into A -> B for every B that g() locks itself (one level).
std::vector<LockOrder> with_calls(const std::vector<LockOrder> &facts);

// ---- text from outside, across files
// -----------------------------------------
//
// One file on its own cannot see that main() reads argv and that a function in
// another file runs it. Each file leaves facts here, and once every file has
// been read resolve_taint() connects them: a call in one file that hands
// outside text to a parameter that reaches a dangerous call in another is a
// finding at the call, with the route it took.

// A parameter of `function` that reaches a dangerous call.
struct TaintSink {
    std::string function;
    size_t param = 0;
    std::string rule; // the finding the call would be, e.g. command-injection
    std::string call; // system, popen, ...
    std::string sink_function; // the function holding the call
    std::string file;
    int sink_line = 0;
};

// A parameter of `function` that is passed on to a parameter of another, at
// the call on `line` of `file`.
struct TaintEdge {
    std::string function;
    size_t param = 0;
    std::string callee;
    size_t callee_param = 0;
    int line = 0;
    std::string file;
};

// A call that hands text from outside to a parameter of a function in another
// file: whatever that parameter reaches there is reported at this call.
struct TaintCaller {
    std::string file;     // the file the call is written in
    std::string function; // the function the call is in
    std::string callee;
    size_t param = 0;
    int line = 0;
    int col = 0;
    FlowStep origin; // where the text entered the program
};

struct TaintDb {
    std::vector<TaintSink> sinks;
    std::vector<TaintEdge> edges;
    std::vector<TaintCaller> callers;
};

// The findings for those calls, once every file is read. Each pair is the file
// the finding is in (the caller's) and the issue.
std::vector<std::pair<std::string, Issue>> resolve_taint(const TaintDb &db);

// Functions of a file, analyzed so far, that return memory only they
// allocated (or NULL) on every return: name -> "malloc", "new" or "new[]"
// (how the caller must release it). Calls to them allocate like malloc.
using Allocators = std::map<std::string, std::string>;

// Functions of a file, analyzed so far, that release a pointer parameter on
// every way out: name -> parameter position -> how ("free", "delete",
// "fclose", ...). Calls to them release that argument.
using Releasers = std::map<std::string, std::map<size_t, std::string>>;

// orders: when given, the function's lock orders are appended to it.
// allocators, releasers: when given, used for its calls and updated with
// fn itself; pass the same maps to a file's functions in order.
std::vector<Issue> analyze_function(const Function &fn,
                                    std::vector<LockOrder> *orders = nullptr,
                                    Allocators *allocators = nullptr,
                                    Releasers *releasers = nullptr);

// Names declared outside any braces: global and file-static variables.
// shared_only: without the static ones, which other files cannot see.
std::set<std::string> file_scope_names(const std::vector<Token> &tokens,
                                       bool shared_only = false);

// Two file-scope mutexes locked in both orders, once per pair: the order
// that comes first in the file, then the opposite one.
std::vector<std::pair<LockOrder, LockOrder>>
lock_inversions(const std::vector<LockOrder> &orders,
                const std::set<std::string> &globals);

// Calls that are not async-signal-safe made directly in a signal handler
// installed in this file: signal(SIG, h), .sa_handler = h, .sa_sigaction =
// h. Reported at the call, with the install line as alloc_line.
std::vector<Issue> signal_unsafe_calls(const std::vector<Token> &tokens,
                                       const std::vector<Function> &fns);

// The classic ways C code is made to do what its author never meant (see
// security.cpp): a format that is not a literal, a command line or a copy
// into a fixed array made from text that comes from outside, gets/mktemp and
// scanf("%s"), credentials written into the program, access() then open(),
// world-writable modes, broken algorithms.
// taint: when given, the file's calls and definitions are recorded in it for
// resolve_taint(), which runs once every file has been read.
std::vector<Issue> security_issues(const std::vector<Token> &tokens,
                                   const std::vector<Function> &fns,
                                   TaintDb *taint = nullptr);

} // namespace lcstatic
