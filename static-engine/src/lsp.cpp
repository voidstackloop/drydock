// `leakcheck lsp`: a minimal Language Server over stdio (JSON-RPC with
// Content-Length framing). No dependencies, no sockets: editors speak to
// stdout/stdin. Supports initialize, textDocument/didOpen, didChange (full
// text) and didClose, publishing the static analyzer's issues as
// diagnostics. Incremental and offline; the same checks as `static`.
#include "analyzer.h"
#include "command.h"
#include "lexer.h"
#include "parser.h"
#include "report.h"

#include <cstdio>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace lcreport {
namespace {

std::string json_escape(const std::string &s) {
    std::string out;
    for (char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if ((unsigned char)c < 0x20) {
                char b[8];
                std::snprintf(b, sizeof b, "\\u%04x", c);
                out += b;
            } else {
                out += c;
            }
        }
    }
    return out;
}

// Enough JSON for LSP input: string member lookup and one nesting level.
std::string member_str(const std::string &obj, const std::string &key) {
    const std::string q = "\"" + key + "\"";
    size_t k = obj.find(q);
    if (k == std::string::npos)
        return {};
    size_t c = obj.find(':', k + q.size());
    if (c == std::string::npos)
        return {};
    size_t v = obj.find('"', c + 1);
    if (v == std::string::npos)
        return {};
    std::string out;
    for (size_t i = v + 1; i < obj.size(); ++i) {
        if (obj[i] == '\\' && i + 1 < obj.size()) {
            char n = obj[i + 1];
            if (n == 'n')
                out += '\n';
            else if (n == 't')
                out += '\t';
            else if (n == 'r')
                out += '\r';
            else
                out += n;
            ++i;
        } else if (obj[i] == '"') {
            break;
        } else {
            out += obj[i];
        }
    }
    return out;
}

long member_num(const std::string &obj, const std::string &key, long dflt) {
    const std::string q = "\"" + key + "\"";
    size_t k = obj.find(q);
    if (k == std::string::npos)
        return dflt;
    size_t c = obj.find(':', k + q.size());
    if (c == std::string::npos)
        return dflt;
    return std::strtol(obj.c_str() + c + 1, nullptr, 10);
}

// The params object at depth 1: {"...","params": { ... }, ...} — finds the
// matching brace of the object that follows "params".
std::string member_obj(const std::string &msg, const std::string &key) {
    const std::string q = "\"" + key + "\"";
    size_t k = msg.find(q);
    if (k == std::string::npos)
        return {};
    size_t b = msg.find('{', k + q.size());
    if (b == std::string::npos)
        return {};
    int depth = 0;
    bool in_str = false;
    for (size_t i = b; i < msg.size(); ++i) {
        if (in_str) {
            if (msg[i] == '\\')
                ++i;
            else if (msg[i] == '"')
                in_str = false;
        } else if (msg[i] == '"') {
            in_str = true;
        } else if (msg[i] == '{') {
            ++depth;
        } else if (msg[i] == '}') {
            if (--depth == 0)
                return msg.substr(b, i - b + 1);
        }
    }
    return {};
}

bool read_message(std::string *out) {
    size_t length = 0;
    std::string line;
    // Header lines end with \r\n; a blank line ends the headers.
    while (std::cin.good()) {
        std::getline(std::cin, line);
        if (!std::cin.good() && line.empty())
            return false;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty())
            break;
        const std::string pre = "Content-Length:";
        if (line.compare(0, pre.size(), pre) == 0)
            length = size_t(std::stoul(line.substr(pre.size())));
    }
    if (length == 0 || length > 64 * 1024 * 1024)
        return false;
    out->assign(length, '\0');
    std::cin.read(out->data(), std::streamsize(length));
    return std::cin.good() || std::cin.gcount() == std::streamsize(length);
}

void send_message(const std::string &body) {
    std::cout << "Content-Length: " << body.size() << "\r\n\r\n" << body
              << std::flush;
}

int lsp_severity(const std::string &rule) {
    if (rule == "memory-leak" || rule == "double-free" ||
        rule == "heap-use-after-free" || rule == "buffer-overflow" ||
        rule == "format-string" || rule == "command-injection")
        return 1; // Error
    return 2;     // Warning
}

std::string analyze_text(const std::string &uri, const std::string &text) {
    std::vector<std::string> diags;
    const auto tokens = lcstatic::lex(text);
    const auto fns = lcstatic::parse_functions(tokens);
    lcstatic::Allocators allocators;
    lcstatic::Releasers releasers;
    std::vector<lcstatic::LockOrder> orders;
    auto emit = [&](const lcstatic::Issue &is) {
        int line = is.line > 0 ? is.line - 1 : 0;
        std::ostringstream d;
        d << "{\"range\":{\"start\":{\"line\":" << line
          << ",\"character\":0},\"end\":{\"line\":" << line
          << ",\"character\":80}},\"severity\":" << lsp_severity(is.rule)
          << ",\"code\":\"" << json_escape(is.rule) << "\",\"source\":\"leakcheck\""
          << ",\"message\":\"" << json_escape(is.message) << "\"}";
        diags.push_back(d.str());
    };
    for (const auto &fn : fns)
        for (const auto &is : lcstatic::analyze_function(fn, &orders,
                                                         &allocators, &releasers))
            emit(is);
    for (const auto &is : lcstatic::signal_unsafe_calls(tokens, fns))
        emit(is);
    lcstatic::TaintDb taint;
    for (const auto &is : lcstatic::security_issues(tokens, fns, &taint))
        emit(is);
    std::ostringstream body;
    body << "{\"jsonrpc\":\"2.0\",\"method\":\"textDocument/publishDiagnostics\""
         << ",\"params\":{\"uri\":\"" << json_escape(uri) << "\",\"diagnostics\":[";
    for (size_t i = 0; i < diags.size() && i < 200; ++i) {
        if (i)
            body << ",";
        body << diags[i];
    }
    body << "]}}";
    return body.str();
}

} // namespace

int run_lsp(const Command & /*command*/) {
    // A log on stderr keeps stdout framing intact when something odd arrives.
    std::map<std::string, std::string> docs;
    bool shutdown = false;
    for (;;) {
        std::string msg;
        if (!read_message(&msg))
            break;
        const std::string method = member_str(msg, "method");
        long id = member_num(msg, "id", -1);
        const bool has_id = msg.find("\"id\"") != std::string::npos;
        auto respond = [&](const std::string &result) {
            if (!has_id)
                return;
            std::ostringstream r;
            r << "{\"jsonrpc\":\"2.0\",\"id\":" << id << ",\"result\":" << result
              << "}";
            send_message(r.str());
        };
        if (method == "initialize") {
            respond("{\"capabilities\":{\"textDocumentSync\":1},"
                    "\"serverInfo\":{\"name\":\"leakcheck\",\"version\":\"1.0.0\"}}");
        } else if (method == "initialized" || method == "exit") {
            if (method == "exit")
                break;
        } else if (method == "shutdown") {
            shutdown = true;
            respond("null");
        } else if (method == "textDocument/didOpen" ||
                   method == "textDocument/didChange") {
            const std::string params = member_obj(msg, "params");
            const std::string doc = member_obj(params, "textDocument");
            const std::string uri = member_str(doc, "uri");
            std::string text = member_str(params, "text");
            if (text.empty() && method == "textDocument/didChange") {
                // contentChanges: [{text: ...}] — take the last full text.
                size_t p = params.rfind("\"text\"");
                if (p != std::string::npos) {
                    size_t q = params.find('"', p + 6);
                    if (q != std::string::npos) {
                        text = member_str(params.substr(p), "text");
                        (void)q;
                    }
                }
            }
            if (text.empty()) {
                auto it = docs.find(uri);
                if (it != docs.end())
                    text = it->second;
            } else {
                docs[uri] = text;
            }
            if (!uri.empty())
                send_message(analyze_text(uri, text));
        } else if (method == "textDocument/didClose") {
            const std::string params = member_obj(msg, "params");
            const std::string uri =
                member_str(member_obj(params, "textDocument"), "uri");
            docs.erase(uri);
            std::ostringstream clear;
            clear << "{\"jsonrpc\":\"2.0\",\"method\":"
                     "\"textDocument/publishDiagnostics\",\"params\":{\"uri\":\""
                  << json_escape(uri) << "\",\"diagnostics\":[]}}";
            send_message(clear.str());
        } else if (has_id) {
            respond("null");
        }
        (void)shutdown;
    }
    return 0;
}

} // namespace lcreport
