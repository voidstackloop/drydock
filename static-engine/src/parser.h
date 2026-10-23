#pragma once
// Finds function definitions in a token stream and turns their bodies into a
// statement tree. Expressions stay as flat token lists.
#include "lexer.h"

#include <memory>
#include <string>
#include <vector>

namespace lcstatic {

struct Stmt {
    enum Kind {
        Block,
        Simple,  // expression or declaration: tokens in a
        If,      // cond a, then s1, else s2
        While,   // cond a, body s1
        DoWhile, // body s1, cond a
        For,     // init a, cond b, step c, body s1; range-for: decl a, range b
        Switch,  // cond a, body s1
        Case,    // case/default label inside a switch
        Return,  // value a
        Break,
        Continue,
        Goto,  // label
        Label, // label
        Try,   // body s1, handlers kids
        Empty
    };
    Kind kind = Empty;
    int line = 0;
    int col = 0;
    int end_line = 0; // Block written with braces: line of its '}'
    bool range_for = false;
    std::vector<Token> a, b, c;
    std::vector<std::unique_ptr<Stmt>> kids;
    std::unique_ptr<Stmt> s1, s2;
    std::string label;
};

struct Function {
    std::string name;
    bool returns_pointer = false; // declared "T *name(...)"
    std::vector<Token> params;
    std::unique_ptr<Stmt> body;
    int line = 0;
    int end_line = 0;
};

std::vector<Function> parse_functions(const std::vector<Token> &toks);

} // namespace lcstatic
