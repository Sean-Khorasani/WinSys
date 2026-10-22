// Script.cpp
// SPDX-License-Identifier: Apache-2.0
// The WinTCP Script engine: a line-oriented language with variables, if/else,
// while, for and CLI command execution. Moved verbatim out of CliCommands.cpp.
//
// Grammar (line-oriented, # comments, ; statement separator):
//   set VAR = EXPR                  ; variable assignment with math/string ops
//   sleep SECONDS                   ; pause execution
//   while COND { ... }              ; loop while condition is true
//   for VAR = START to END { ... }  ; numeric range loop
//   if COND { ... } [else { ... }]  ; conditional
//   CMD [args...]                   ; execute any CLI command
//   break / continue                ; loop control
//   return [CODE]                   ; exit script with code
//
// Expressions support: + - * / % ( ), string concat with +, comparisons
//   == != < > <= >=, logical && || !, variables $VAR / ${VAR} (a bare NAME
//   that names a variable also reads it, so `while N < 2` works).
#include "Script.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cwchar>
#include <cwctype>
#include <fstream>
#include <functional>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include "CliCommands.h"   // RunCliCommand - the dispatcher a script step calls
#include "Utils.h"         // WideToUtf8, WriteOut, WriteErr

namespace wintcp {
namespace Script {


    // -----------------------------------------------------------------------
    // Token types for the script parser
    // -----------------------------------------------------------------------
    enum class TokenType {
        EndOfFile,
        Identifier,      // variable name or command name
        Number,          // numeric literal
        String,          // quoted string
        Equals,          // =
        Plus,            // +
        Minus,           // -
        Multiply,        // *
        Divide,          // /
        Modulo,          // %
        LParen,          // (
        RParen,          // )
        LBrace,          // {
        RBrace,          // }
        Comma,           // ,
        Semicolon,       // ;
        While,           // while
        For,             // for
        If,              // if
        Else,            // else
        NumberRange,     // START to END in for
        LessThan,        // <
        GreaterThan,     // >
        LessEqual,       // <=
        GreaterEqual,    // >=
        EqualEqual,      // ==
        NotEqual,        // !=
        Bang,            // !
        And,             // &&
        Or,              // ||
        Not,             // not (unary)
        AtSign,          // @ (variable reference)
        Command,         // CLI command name
        Keyword,         // sleep, return, break, continue
        StringValue,     // unquoted string value
        Unknown,         // unrecognized token
        EOFToken         // end of file marker
    };

    struct Token {
        TokenType type;
        std::wstring value;
        size_t lineNum;
    };

    // Convert a token back into script text without losing string boundaries.
    // The parser stores block/command bodies as text and tokenizes them again
    // during execution, so a string token must retain its quotes and escapes.
    std::wstring tokenToSource(const Token& token) {
        if (token.type != TokenType::String) return token.value;
        std::wstring source = L"\"";
        for (wchar_t ch : token.value) {
            if (ch == L'\\' || ch == L'\"') source += L'\\';
            source += ch;
        }
        source += L'\"';
        return source;
    }

    void writeError(size_t line, const std::wstring& msg);

    // -----------------------------------------------------------------------
    // Error handling for parser
    // -----------------------------------------------------------------------
    struct ParseError {
        size_t line = 0;
        std::wstring message;
    };
    
    thread_local std::vector<ParseError> g_parseErrors;
    
    void writeError(size_t line, const std::wstring& msg) {
        g_parseErrors.push_back({line, msg});
    }
    
    void clearParseErrors() {
        g_parseErrors.clear();
    }
    
    bool hasParseErrors() {
        return !g_parseErrors.empty();
    }
    
    std::wstring getFirstParseError() {
        if (g_parseErrors.empty()) return L"";
        return L"line " + std::to_wstring(g_parseErrors[0].line) + L": " + g_parseErrors[0].message;
    }

    // -----------------------------------------------------------------------
    // Simple tokenizer: splits script text into tokens
    // -----------------------------------------------------------------------
    class Tokenizer {
    public:
        Tokenizer(const std::wstring& text) : m_text(text), m_pos(0), m_line(1) {}
        
        void clearErrors() { clearParseErrors(); }

        std::vector<Token> tokenize() {
            std::vector<Token> tokens;
            while (m_pos < m_text.size()) {
                skipWhitespace(tokens);
                if (m_pos >= m_text.size()) break;

                // Comment
                if (m_text[m_pos] == L'#') {
                    skipComment();
                    continue;
                }

                // String literal
                if (m_text[m_pos] == L'"') {
                    tokens.push_back(tokenizeString());
                    continue;
                }

                // Number
                const bool unaryMinus = m_text[m_pos] == L'-' && m_pos + 1 < m_text.size() &&
                    iswdigit(m_text[m_pos + 1]) &&
                    (tokens.empty() || tokens.back().type == TokenType::Equals ||
                     tokens.back().type == TokenType::Plus || tokens.back().type == TokenType::Minus ||
                     tokens.back().type == TokenType::Multiply || tokens.back().type == TokenType::Divide ||
                     tokens.back().type == TokenType::Modulo || tokens.back().type == TokenType::LParen ||
                     tokens.back().type == TokenType::Comma);
                if (iswdigit(m_text[m_pos]) || unaryMinus) {
                    tokens.push_back(tokenizeNumber());
                    continue;
                }

                // Identifiers, keywords, and $VAR references
            if (iswalpha(m_text[m_pos]) || m_text[m_pos] == L'@' || m_text[m_pos] == L'$') {
                    tokens.push_back(tokenizeIdentifier());
                    continue;
                }

                // Single character tokens
                wchar_t ch = m_text[m_pos++];
                switch (ch) {
                    case L'=': {
                        if (m_pos < m_text.size() && m_text[m_pos] == L'=') {
                            ++m_pos;
                            tokens.push_back({TokenType::EqualEqual, L"==", m_line});
                        } else {
                            tokens.push_back({TokenType::Equals, L"=", m_line});
                        }
                        break;
                    }
                    case L'+': tokens.push_back({TokenType::Plus, L"+", m_line}); break;
                    case L'-': tokens.push_back({TokenType::Minus, L"-", m_line}); break;
                    case L'*': tokens.push_back({TokenType::Multiply, L"*", m_line}); break;
                    case L'/': tokens.push_back({TokenType::Divide, L"/", m_line}); break;
                    case L'%': tokens.push_back({TokenType::Modulo, L"%", m_line}); break;
                    case L'(': tokens.push_back({TokenType::LParen, L"(", m_line}); break;
                    case L')': tokens.push_back({TokenType::RParen, L")", m_line}); break;
                    case L'{': tokens.push_back({TokenType::LBrace, L"{", m_line}); break;
                    case L'}': tokens.push_back({TokenType::RBrace, L"}", m_line}); break;
                    case L',': tokens.push_back({TokenType::Comma, L",", m_line}); break;
                    case L';': tokens.push_back({TokenType::Semicolon, L";", m_line}); break;
                    case L'<': {
                        // Check for <= or <>
                        if (m_pos < m_text.size() && m_text[m_pos] == L'=') {
                            m_pos++;
                            tokens.push_back({TokenType::LessEqual, L"<=", m_line});
                        } else {
                            tokens.push_back({TokenType::LessThan, L"<", m_line});
                        }
                        break;
                    }
                    case L'>': {
                        // Check for >= or >>
                        if (m_pos < m_text.size() && m_text[m_pos] == L'=') {
                            m_pos++;
                            tokens.push_back({TokenType::GreaterEqual, L">=", m_line});
                        } else {
                            tokens.push_back({TokenType::GreaterThan, L">", m_line});
                        }
                        break;
                    }
                    case L'!': {
                        if (m_pos < m_text.size() && m_text[m_pos] == L'=') {
                            m_pos++;
                            tokens.push_back({TokenType::NotEqual, L"!=", m_line});
                        } else {
                            tokens.push_back({TokenType::Bang, L"!", m_line});
                        }
                        break;
                    }
                    case L'&': {
                        if (m_pos < m_text.size() && m_text[m_pos] == L'&') {
                            m_pos += 1;
                            tokens.push_back({TokenType::And, L"&&", m_line});
                        } else {
                            tokens.push_back({TokenType::Unknown, L"&", m_line}); // single & is invalid
                        }
                        break;
                    }
                    case L'|': {
                        if (m_pos < m_text.size() && m_text[m_pos] == L'|') {
                            m_pos += 1;
                            tokens.push_back({TokenType::Or, L"||", m_line});
                        } else {
                            tokens.push_back({TokenType::Unknown, L"|", m_line}); // single | is invalid
                        }
                        break;
                    }
                    default: break;
                }
            }
            tokens.push_back({TokenType::EndOfFile, L"", m_line});
            return tokens;
        }

    private:
        void skipWhitespace(std::vector<Token>& tokens) {
            while (m_pos < m_text.size()) {
                wchar_t ch = m_text[m_pos];
                if (ch == L'\\' && m_pos + 1 < m_text.size() &&
                    (m_text[m_pos + 1] == L'\n' ||
                     (m_text[m_pos + 1] == L'\r' && m_pos + 2 < m_text.size() &&
                      m_text[m_pos + 2] == L'\n'))) {
                    // An unquoted backslash-newline continues the current
                    // statement rather than emitting a separator. Accept
                    // both LF and Windows CRLF line endings.
                    if (m_text[m_pos + 1] == L'\r') m_pos += 3;
                    else m_pos += 2;
                    ++m_line;
                } else if (ch == L'\n') {
                    // Newlines separate statements just like semicolons. Do
                    // not emit duplicate separators for blank lines.
                    if (!tokens.empty() && tokens.back().type == TokenType::LBrace) {
                        // The parser serializes block content, where spaces
                        // already separate tokens and `;` remains explicit.
                        // Dropping this leading separator avoids an empty
                        // first command when a block opens on its own line.
                    } else if (tokens.empty() || tokens.back().type != TokenType::Semicolon) {
                        tokens.push_back({TokenType::Semicolon, L";", m_line});
                    }
                    ++m_line;
                    ++m_pos;
                } else if (ch == L' ' || ch == L'\t' || ch == L'\r') {
                    m_pos++;
                } else break;
            }
        }

        void skipComment() {
            m_pos++; // skip #
            while (m_pos < m_text.size() && m_text[m_pos] != L'\n') m_pos++;
        }

        Token tokenizeString() {
            std::wstring value;
            m_pos++; // skip opening "
            while (m_pos < m_text.size() && m_text[m_pos] != L'"') {
                if (m_text[m_pos] == L'\n') ++m_line;
                if (m_text[m_pos] == L'\\' && m_pos + 1 < m_text.size()) {
                    m_pos++; // skip escape
                    value += m_text[m_pos++];
                } else {
                    value += m_text[m_pos++];
                }
            }
            if (m_pos < m_text.size()) {
                m_pos++; // skip closing "
            } else {
                writeError(m_line, L"unterminated string literal");
            }
            return {TokenType::String, value, m_line};
        }

        Token tokenizeNumber() {
            std::wstring numStr;
            bool hadDot = false;
            if (m_pos < m_text.size() && m_text[m_pos] == L'-') {
                numStr += m_text[m_pos++];
            }
            while (m_pos < m_text.size()) {
                wchar_t ch = m_text[m_pos];
                if (iswdigit(ch)) {
                    numStr += ch;
                    m_pos++;
                } else if (ch == L'.' && !hadDot) {
                    hadDot = true;
                    numStr += ch;
                    m_pos++;
                } else break;
            }
            Token t;
            t.type = numStr.find(L'.') != std::wstring::npos ? TokenType::Number : TokenType::Number;
            t.value = numStr;
            t.lineNum = m_line;
            return t;
        }

        Token tokenizeIdentifier() {
            std::wstring word;
            // Handle @VAR or $VAR reference, or plain identifier
            if (m_text[m_pos] == L'@' || m_text[m_pos] == L'$') {
                word += m_text[m_pos++];
            }
            if (word == L"$") {
                // Support ${NAME} while retaining a token value compatible
                // with the ordinary $NAME expansion path.
                if (m_pos < m_text.size() && m_text[m_pos] == L'{') {
                    ++m_pos;
                    while (m_pos < m_text.size() && m_text[m_pos] != L'}') {
                        word += m_text[m_pos++];
                    }
                    if (m_pos < m_text.size() && m_text[m_pos] == L'}') ++m_pos;
                } else {
                    while (m_pos < m_text.size() && (iswalnum(m_text[m_pos]) || m_text[m_pos] == L'_')) {
                        word += m_text[m_pos++];
                    }
                }
            } else {
                while (m_pos < m_text.size() && (iswalnum(m_text[m_pos]) || m_text[m_pos] == L'_')) {
                    word += m_text[m_pos++];
                }
            }
            // Check for keywords
            Token t;
            t.lineNum = m_line;
            
            // Convert to lower for keyword check
            std::wstring lower = word;
            for (wchar_t& c : lower) c = static_cast<wchar_t>(::tolower(c));
            
            if (lower == L"while") {
                t.type = TokenType::While;
                t.value = word;
            }
            else if (lower == L"for") {
                t.type = TokenType::For;
                t.value = word;
            }
            else if (lower == L"if") {
                t.type = TokenType::If;
                t.value = word;
            }
            else if (lower == L"else") {
                t.type = TokenType::Else;
                t.value = word;
            }
            else if (lower == L"sleep") {
                t.type = TokenType::Keyword;
                t.value = word;
            }
            else if (lower == L"return") {
                t.type = TokenType::Keyword;
                t.value = word;
            }
            else if (lower == L"break") {
                t.type = TokenType::Keyword;
                t.value = word;
            }
            else if (lower == L"continue") {
                t.type = TokenType::Keyword;
                t.value = word;
            }
            else if (lower == L"set") {
                t.type = TokenType::Keyword;
                t.value = word;
            }
            else if (lower == L"to") {
                t.type = TokenType::Keyword;
                t.value = word;
            }
            else if (lower == L"not") {
                t.type = TokenType::Not;
                t.value = word;
            }
            else if (word.front() == L'@') {
                // @NAME is a variable reference just like $NAME. Keep it an
                // identifier so assignment, expression, and argument paths
                // all see the same token category.
                t.type = TokenType::Identifier;
                t.value = word;
            }
            else if (iswdigit(word.front()) || (word.size() > 1 && word.front() == L'-' && iswdigit(word[1]))) {
                t.type = TokenType::Number;
                t.value = word;
            }
            else if (word.find(L'+') != std::wstring::npos || word.find(L'-') != std::wstring::npos) {
                t.type = TokenType::StringValue;
                t.value = word;
            }
            else {
                t.type = TokenType::Identifier;
                t.value = word;
            }
            return t;
        }

        const std::wstring& m_text;
        size_t m_pos;
        size_t m_line;
    };

    // -----------------------------------------------------------------------
    // Parser: converts tokens into an AST of statements
    // -----------------------------------------------------------------------
    class Parser {
    public:
        Parser(const std::vector<Token>& tokens) : m_tokens(tokens), m_pos(0) {}

        bool parse(std::vector<std::wstring>& statements) {
            while (m_pos < m_tokens.size()) {
                while (m_pos < m_tokens.size() && m_tokens[m_pos].type == TokenType::Semicolon) {
                    ++m_pos;
                }
                if (m_pos >= m_tokens.size()) break;
                const Token& tok = m_tokens[m_pos];
                if (tok.type == TokenType::EndOfFile) break;
                
                std::wstring stmt;
                if (!parseStatement(stmt)) {
                    writeError(tok.lineNum, L"syntax error near: " + tok.value);
                    return false;
                }
                if (!stmt.empty()) statements.push_back(stmt);
                // Skip semicolon if present
                if (m_pos < m_tokens.size() && m_tokens[m_pos].type == TokenType::Semicolon) {
                    m_pos++;
                }
            }
            return true;
        }

    private:
        // Blocks are stored as source text and parsed again by the runtime.
        // Validate each reconstructed body now as well, so --dry-run and the
        // top-level parse catch nested syntax errors before any command runs.
        bool validateBlockBody(const std::wstring& body) {
            Tokenizer tokenizer(body);
            const auto bodyTokens = tokenizer.tokenize();
            if (hasParseErrors()) return false;

            Parser parser(bodyTokens);
            std::vector<std::wstring> statements;
            return parser.parse(statements);
        }

        bool parseStatement(std::wstring& out) {
            const Token& tok = m_tokens[m_pos];
            
            // Variable assignment: VAR = EXPR (also handles "set VAR = EXPR")
            bool isSet = (tok.type == TokenType::Keyword && tok.value == L"set");
            if (isSet) {
                // "set VAR = EXPR"
                if (m_pos + 3 < m_tokens.size() &&
                    m_tokens[m_pos + 1].type == TokenType::Identifier &&
                    m_tokens[m_pos + 2].type == TokenType::Equals) {
                    size_t varIdx = m_pos + 1;
                    m_pos = varIdx + 2; // skip identifier and =
                    out = m_tokens[varIdx].value + L" = " + parseExpression();
                    while (m_pos < m_tokens.size() && m_tokens[m_pos].type != TokenType::Semicolon &&
                           m_tokens[m_pos].type != TokenType::RBrace) {
                        out += L" " + m_tokens[m_pos].value;
                        m_pos++;
                    }
                    return true;
                }
            } else if (tok.type == TokenType::Identifier && m_pos + 2 < m_tokens.size() &&
                       m_tokens[m_pos + 1].type == TokenType::Equals) {
                // "VAR = EXPR"
                size_t varIdx = m_pos;
                m_pos = varIdx + 2; // skip identifier and =
                out = m_tokens[varIdx].value + L" = " + parseExpression();
                while (m_pos < m_tokens.size() && m_tokens[m_pos].type != TokenType::Semicolon &&
                       m_tokens[m_pos].type != TokenType::RBrace) {
                    out += L" " + m_tokens[m_pos].value;
                    m_pos++;
                }
                return true;
            }

            // Sleep command: sleep SECONDS
            if (tok.type == TokenType::Keyword && tok.value == L"sleep") {
                m_pos++; // skip sleep
                if (m_pos < m_tokens.size() && m_tokens[m_pos].type == TokenType::Number) {
                    out = L"sleep " + m_tokens[m_pos].value;
                    m_pos++;
                } else {
                    writeError(tok.lineNum, L"sleep: expected a numeric duration");
                    return false;
                }
                return true;
            }

            // While loop: while COND { ... }
            if (tok.type == TokenType::While) {
                m_pos++; // skip while
                std::wstring condition = parseCondition();
                out = L"while " + condition + L" {";
                
                // parseCondition stops immediately before the opening brace.
                if (m_pos >= m_tokens.size() || m_tokens[m_pos].type != TokenType::LBrace) {
                    writeError(tok.lineNum, L"while: expected '{'");
                    return false;
                }
                int braceDepth = 1;
                ++m_pos; // skip opening brace
                std::wstring body;
                while (m_pos < m_tokens.size() && braceDepth > 0) {
                    if (m_tokens[m_pos].type == TokenType::LBrace) braceDepth++;
                    else if (m_tokens[m_pos].type == TokenType::RBrace) {
                        braceDepth--;
                        if (braceDepth == 0) break;
                    }
                    if (braceDepth > 0) {
                        if (m_tokens[m_pos].type == TokenType::Semicolon) body += L"; ";
                        else body += tokenToSource(m_tokens[m_pos]) + L" ";
                    }
                    m_pos++;
                }
                if (m_pos < m_tokens.size() && m_tokens[m_pos].type == TokenType::RBrace) {
                    ++m_pos;
                } else {
                    writeError(tok.lineNum, L"while: missing '}'");
                    return false;
                }
                if (!validateBlockBody(body)) return false;
                out += body + L"}";
                return true;
            }

            // For loop: for VAR = START to END { ... }
            if (tok.type == TokenType::For) {
                m_pos++; // skip for
                // Parse: for VAR = START to END { body }
                if (m_pos + 4 < m_tokens.size() &&
                    m_tokens[m_pos].type == TokenType::Identifier &&
                    m_tokens[m_pos + 1].type == TokenType::Equals &&
                    (m_tokens[m_pos + 2].type == TokenType::Number || m_tokens[m_pos + 2].type == TokenType::Identifier) &&
                    m_tokens[m_pos + 3].type == TokenType::Keyword && m_tokens[m_pos + 3].value == L"to") {

                    std::wstring varName = m_tokens[m_pos].value;
                    std::wstring startVal = m_tokens[m_pos + 2].value;
                    std::wstring endVal = m_tokens[m_pos + 4].value;
                    m_pos += 5; // skip var, =, start, to, end

                    // Extract body until RBrace
                    int braceDepth = 1;
                    std::wstring body;
                    // Like if/while, allow the opening brace to begin the
                    // next physical line after the loop range.
                    while (m_pos < m_tokens.size() &&
                           m_tokens[m_pos].type == TokenType::Semicolon) {
                        ++m_pos;
                    }
                    if (m_pos >= m_tokens.size() || m_tokens[m_pos].type != TokenType::LBrace) {
                        writeError(tok.lineNum, L"for: expected '{'");
                        return false;
                    }
                    ++m_pos;
                    while (m_pos < m_tokens.size() && braceDepth > 0) {
                        if (m_tokens[m_pos].type == TokenType::LBrace) braceDepth++;
                        else if (m_tokens[m_pos].type == TokenType::RBrace) {
                            braceDepth--;
                            if (braceDepth == 0) break;
                        }
                        if (braceDepth > 0) {
                            if (m_tokens[m_pos].type == TokenType::Semicolon) body += L"; ";
                            else body += tokenToSource(m_tokens[m_pos]) + L" ";
                        }
                        ++m_pos;
                    }
                    if (braceDepth != 0 || m_pos >= m_tokens.size() ||
                        m_tokens[m_pos].type != TokenType::RBrace) {
                        writeError(tok.lineNum, L"for: missing '}'");
                        return false;
                    }
                    ++m_pos;

                    if (!validateBlockBody(body)) return false;
                    out = L"for " + varName + L" = " + startVal + L" to " +
                          endVal + L" { " + body + L" }";
                    return true;
                }
            }

            // If/else conditional: if COND { ... } [else { ... }]
            if (tok.type == TokenType::If) {
                m_pos++; // skip if
                std::wstring condition = parseCondition();
                out = L"if " + condition + L" {";
                
                int braceDepth = 1;
                if (m_pos >= m_tokens.size() || m_tokens[m_pos].type != TokenType::LBrace) {
                    writeError(tok.lineNum, L"if: expected '{'");
                    return false;
                }
                ++m_pos;
                std::wstring thenBody;
                while (m_pos < m_tokens.size() && braceDepth > 0) {
                    if (m_tokens[m_pos].type == TokenType::LBrace) braceDepth++;
                    else if (m_tokens[m_pos].type == TokenType::RBrace) {
                        braceDepth--;
                        if (braceDepth == 0) break;
                    }
                    if (braceDepth > 0) {
                        if (m_tokens[m_pos].type == TokenType::Semicolon) thenBody += L"; ";
                        else thenBody += tokenToSource(m_tokens[m_pos]) + L" ";
                    }
                    m_pos++;
                }
                if (m_pos < m_tokens.size() && m_tokens[m_pos].type == TokenType::RBrace) {
                    ++m_pos;
                } else {
                    writeError(tok.lineNum, L"if: missing '}'");
                    return false;
                }
                if (!validateBlockBody(thenBody)) return false;
                out += thenBody + L"}";
                
                // A newline is a normal statement separator, but `else`
                // may follow the closing brace on the next line.
                while (m_pos + 1 < m_tokens.size() &&
                       m_tokens[m_pos].type == TokenType::Semicolon &&
                       m_tokens[m_pos + 1].type == TokenType::Else) {
                    ++m_pos;
                }

                // Check for else
                if (m_pos < m_tokens.size() && m_tokens[m_pos].type == TokenType::Else) {
                    m_pos++; // skip else
                    if (m_pos < m_tokens.size() && m_tokens[m_pos].type == TokenType::LBrace) {
                        m_pos++; // skip opening brace
                        braceDepth = 1;
                        std::wstring elseBody;
                        while (m_pos < m_tokens.size() && braceDepth > 0) {
                            if (m_tokens[m_pos].type == TokenType::LBrace) braceDepth++;
                            else if (m_tokens[m_pos].type == TokenType::RBrace) {
                                braceDepth--;
                                if (braceDepth == 0) break;
                            }
                            if (braceDepth > 0) {
                                if (m_tokens[m_pos].type == TokenType::Semicolon) elseBody += L"; ";
                                else elseBody += tokenToSource(m_tokens[m_pos]) + L" ";
                            }
                            m_pos++;
                        }
                        if (m_pos < m_tokens.size() && m_tokens[m_pos].type == TokenType::RBrace) {
                            ++m_pos;
                        } else {
                            writeError(tok.lineNum, L"else: missing '}'");
                            return false;
                        }
                        if (!validateBlockBody(elseBody)) return false;
                        out += L" else {" + elseBody + L"}";
                    } else {
                        writeError(tok.lineNum, L"else: expected '{'");
                        return false;
                    }
                }
                return true;
            }

            // Regular command: CMD [args...]
            if (tok.type == TokenType::Command || tok.type == TokenType::Identifier) {
                out = tok.value;
                m_pos++;
                // Collect remaining tokens until semicolon or brace
                while (m_pos < m_tokens.size() && m_tokens[m_pos].type != TokenType::Semicolon &&
                       m_tokens[m_pos].type != TokenType::RBrace && m_tokens[m_pos].type != TokenType::EndOfFile) {
                    out += L" " + tokenToSource(m_tokens[m_pos]);
                    m_pos++;
                }
                return true;
            }

            // break / continue
            if (tok.type == TokenType::Keyword) {
                std::wstring lower = tok.value;
                for (wchar_t& c : lower) c = static_cast<wchar_t>(::tolower(c));
                if (lower == L"break") { out = L"break"; m_pos++; return true; }
                if (lower == L"continue") { out = L"continue"; m_pos++; return true; }
            }

            // return [CODE]
            if (tok.type == TokenType::Keyword && tok.value == L"return") {
                m_pos++; // skip return
                out = L"return";
                if (m_pos < m_tokens.size() && m_tokens[m_pos].type == TokenType::Number) {
                    out += L" " + m_tokens[m_pos].value;
                    m_pos++;
                }
                return true;
            }

            writeError(tok.lineNum, L"unknown statement: " + tok.value);
            return false;
        }

        std::wstring parseExpression() {
            // Simple expression parser for assignments
            // Handles: numbers, variables, +, -, *, /, %, (), comparisons
            return parseBinaryExpr(0);
        }

        std::wstring parseBinaryExpr(int minPrec) {
            std::wstring left = parsePrimary();
            
            while (m_pos < m_tokens.size()) {
                TokenType op = m_tokens[m_pos].type;
                int precedence = 0;
                if (op == TokenType::Plus || op == TokenType::Minus) {
                    precedence = 1;
                } else if (op == TokenType::Multiply || op == TokenType::Divide ||
                           op == TokenType::Modulo) {
                    precedence = 2;
                }
                if (precedence < minPrec || precedence == 0) break;

                const std::wstring opText = m_tokens[m_pos].value;
                ++m_pos; // consume operator
                // Binary operators are left-associative: recurse with one
                // greater precedence so operators of equal precedence remain
                // grouped from left to right while multiplication/division
                // binds more tightly than addition/subtraction.
                std::wstring right = parseBinaryExpr(precedence + 1);
                left = L"(" + left + L" " + opText + L" " + right + L")";
            }
            return left;
        }

        std::wstring parsePrimary() {
            if (m_pos >= m_tokens.size()) return L"";
            
            TokenType type = m_tokens[m_pos].type;
            
            if (type == TokenType::Number) {
                std::wstring val = m_tokens[m_pos].value;
                m_pos++;
                return val;
            }

            if (type == TokenType::String) {
                std::wstring val = L"\"";
                for (wchar_t ch : m_tokens[m_pos].value) {
                    if (ch == L'\\' || ch == L'\"') val += L'\\';
                    val += ch;
                }
                val += L'\"';
                ++m_pos;
                return val;
            }
            
            if (type == TokenType::Identifier) {
                std::wstring val = m_tokens[m_pos].value;
                m_pos++;
                // Check if it's a variable reference $VAR or @VAR
                if (val.size() > 1 && (val[0] == L'$' || val[0] == L'@')) {
                    // Variable lookup - will be resolved at execution time
                    return val;
                }
                return val;
            }
            
            if (type == TokenType::LParen) {
                m_pos++; // skip (
                std::wstring expr = parseExpression();
                if (m_pos < m_tokens.size() && m_tokens[m_pos].type == TokenType::RParen) {
                    m_pos++; // skip )
                }
                return expr;
            }
            
            return L"";
        }

        std::wstring parseCondition() {
            // Parse a boolean condition for while/if
            // Collect tokens until we hit { or EOF, preserving the original text
            std::wstring result;
            int parenDepth = 0;
            while (m_pos < m_tokens.size()) {
                TokenType t = m_tokens[m_pos].type;
                if (t == TokenType::LBrace) break;
                if (t == TokenType::EndOfFile) break;
                if (t == TokenType::Semicolon) {
                    // Permit a line break between the condition and the
                    // opening brace, but otherwise stop at statement end.
                    if (m_pos + 1 < m_tokens.size() &&
                        m_tokens[m_pos + 1].type == TokenType::LBrace) {
                        ++m_pos;
                        break;
                    }
                    break;
                }
                if (t == TokenType::LParen) parenDepth++;
                else if (t == TokenType::RParen) parenDepth--;
                if (parenDepth < 0) break;
                if (!result.empty()) result += L" ";
                result += m_tokens[m_pos].value;
                m_pos++;
            }
            return result;
        }

        const std::vector<Token>& m_tokens;
        size_t m_pos;
    };

    // -----------------------------------------------------------------------
    // Runtime value types
    // -----------------------------------------------------------------------
    enum class ValueType { Number, String, Unknown };
    
    struct ScriptValue {
        ValueType type = ValueType::Unknown;
        double numVal = 0.0;
        std::wstring strVal;
        
        ScriptValue() = default;
        ScriptValue(double n) : type(ValueType::Number), numVal(n) {}
        ScriptValue(const std::wstring& s) : type(ValueType::String), strVal(s) {}
        
        operator double() const { return numVal; }
        operator const std::wstring&() const { return strVal; }
    };
    
    // -----------------------------------------------------------------------
    // Variable store: holds string and numeric variables
    // -----------------------------------------------------------------------
    class VariableStore {
    public:
        void set(const std::wstring& name, const std::wstring& value) {
            m_vars[name] = value;
            m_numVars.erase(name);
        }
        
        void setNum(const std::wstring& name, double value) {
            m_numVars[name] = value;
            // Keep a textual representation too, so command argument
            // expansion and string concatenation can use loop variables.
            m_vars[name] = std::to_wstring(value);
        }
        
        std::wstring getString(const std::wstring& name) const {
            auto it = m_vars.find(name);
            if (it != m_vars.end()) return it->second;
            return L""; // not found
        }
        
        double getNum(const std::wstring& name) const {
            auto it = m_numVars.find(name);
            if (it != m_numVars.end()) return it->second;
            // Try to parse string as number
            auto sit = m_vars.find(name);
            if (sit != m_vars.end()) {
                try { return std::stod(WideToUtf8(sit->second)); } catch (...) { return 0; }
            }
            return 0;
        }
        
        bool exists(const std::wstring& name) const {
            return m_vars.count(name) > 0 || m_numVars.count(name) > 0;
        }
        
        void define(const std::wstring& name, const std::wstring& value) {
            m_vars[name] = value;
        }
        
    private:
        std::map<std::wstring, std::wstring> m_vars;    // string variables
        std::map<std::wstring, double> m_numVars;      // numeric variables
    };

    // Helper: extract the body inside braces from a statement
    std::wstring extractBraceBody(const std::wstring& statement, const std::vector<Token>& /*tokens*/) {
        // Find first { and matching }
        size_t lbr = statement.find(L'{');
        if (lbr == std::wstring::npos) return L"";
        int depth = 1;
        bool inString = false;
        bool escaped = false;
        size_t i = lbr + 1;
        while (i < statement.size() && depth > 0) {
            const wchar_t ch = statement[i];
            if (inString) {
                if (escaped) escaped = false;
                else if (ch == L'\\') escaped = true;
                else if (ch == L'"') inString = false;
            } else if (ch == L'"') {
                inString = true;
            } else if (ch == L'{') {
                depth++;
            } else if (ch == L'}') {
                depth--;
                if (depth == 0) return statement.substr(lbr + 1, i - lbr - 1);
            }
            i++;
        }
        return L"";
    }

    // Helper: extract condition from while/if statement
    std::wstring extractCondition(const std::wstring& statement, const std::vector<Token>& /*tokens*/) {
        // Find first { and return everything before it (minus the keyword)
        size_t lbr = statement.find(L'{');
        if (lbr == std::wstring::npos) return statement;
        std::wstring header = statement.substr(0, lbr);
        // Remove leading keyword (while/if/for)
        size_t space = header.find(L' ');
        if (space != std::wstring::npos) {
            header = header.substr(space + 1);
        }
        return header;
    }

    // Helper: parse for loop header: for VAR = START to END
    bool parseForHeader(const std::wstring& statement, const std::vector<Token>& /*tokens*/,
                        std::wstring& varName, std::wstring& startStr, std::wstring& endStr) {
        // Format: for VAR = START to END { ... }
        std::wstring header = statement;
        size_t lbr = header.find(L'{');
        if (lbr != std::wstring::npos) header = header.substr(0, lbr);
        // Remove "for " prefix
        if (header.find(L"for ") == 0) header = header.substr(4);
        // Split by spaces, preserving = and to as tokens
        std::vector<std::wstring> parts;
        std::wstring current;
        for (wchar_t c : header) {
            if (c == L' ' || c == L'\t') {
                if (!current.empty()) { parts.push_back(current); current.clear(); }
            } else if (c == L'=') {
                if (!current.empty()) { parts.push_back(current); current.clear(); }
                current = L"=";
            } else {
                current += c;
            }
        }
        if (!current.empty()) parts.push_back(current);
        if (parts.size() >= 5 && parts[1] == L"=" && parts[3] == L"to") {
            varName = parts[0];
            startStr = parts[2];
            endStr = parts[4];
            return true;
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Execute a single parsed statement
    // -----------------------------------------------------------------------
    struct ExecResult {
        bool continueExecution = true;  // false = exit script
        int exitCode = 0;
        std::wstring description;
        bool breakLoop = false;
        bool continueLoop = false;
    };
    
    // Forward declarations for helpers defined below executeStatement
    bool evalCondition(const std::vector<Token>& tokens, size_t start, size_t end, VariableStore& vars);
    std::wstring parseExpressionForExecution(const std::vector<Token>& tokens, size_t startPos, VariableStore& vars);
    std::wstring expandVariables(const std::wstring& input, VariableStore& vars);

    ExecResult executeStatement(const std::wstring& statement, VariableStore& vars,
                                std::function<int(const std::wstring&, const std::vector<std::wstring>&)> runCmd,
                                unsigned& sleepAccumulator) {
        ExecResult result;
        
        // Parse the statement into tokens for execution
        Tokenizer tok(statement);
        auto tokens = tok.tokenize();
        
        if (tokens.empty() || tokens[0].type == TokenType::EndOfFile) {
            result.continueExecution = true;
            return result;
        }
        
        // Dispatch based on first token
        const Token& first = tokens[0];
        
        // Variable assignment: VAR = EXPR or set VAR = EXPR
        if (first.type == TokenType::Identifier && first.value != L"set") {
            // Could be "VAR = EXPR" assignment
            // Check if next token is Equals
            if (tokens.size() > 2 && tokens[1].type == TokenType::Equals) {
                // Assignment: VAR = EXPR
                std::wstring varName = first.value;
                // Strip $ or @ prefix from variable name if present
                if (!varName.empty() && (varName[0] == L'$' || varName[0] == L'@')) {
                    varName = varName.substr(1);
                }
                std::wstring expr = parseExpressionForExecution(tokens, 2, vars);
                vars.set(varName, expr);
                result.continueExecution = true;
                return result;
            }
        }

        // "set VAR = EXPR"
        if (first.type == TokenType::Keyword && first.value == L"set") {
            if (tokens.size() < 4 || tokens[1].type != TokenType::Identifier || tokens[2].type != TokenType::Equals) {
                writeError(0, L"invalid set syntax: expected 'set VAR = EXPR'");
                result.continueExecution = true;
                return result;
            }
            std::wstring varName = tokens[1].value;
            // Strip $ or @ prefix from variable name if present
            if (!varName.empty() && (varName[0] == L'$' || varName[0] == L'@')) {
                varName = varName.substr(1);
            }
            std::wstring exprValue = parseExpressionForExecution(tokens, 3, vars);
            vars.set(varName, exprValue);
            result.continueExecution = true;
            return result;
        }
        
        // sleep SECONDS
        if (first.type == TokenType::Keyword && first.value == L"sleep") {
            if (tokens.size() < 2 || tokens[1].type != TokenType::Number) {
                writeError(0, L"sleep requires a seconds value");
                result.continueExecution = false;
                result.exitCode = 2;
                return result;
            }
            try {
                double seconds = std::stod(WideToUtf8(tokens[1].value));
                if (!std::isfinite(seconds) || seconds < 0.0 || seconds > 86400.0) {
                    writeError(0, L"sleep value must be between 0 and 86400 seconds");
                    result.continueExecution = false;
                    result.exitCode = 2;
                    return result;
                }
                // Sleep where the statement executes, including inside a
                // nested block. The old accumulator was discarded by loops
                // and by the top-level runner, so sleep silently did nothing.
                std::this_thread::sleep_for(
                    std::chrono::duration<double>(seconds));
                sleepAccumulator = 0;
                result.continueExecution = true;
            } catch (...) {
                writeError(0, L"invalid sleep value");
                result.continueExecution = false;
                result.exitCode = 2;
            }
            return result;
        }
        
        // while COND { ... }
        if (first.type == TokenType::While) {
            // Re-tokenize the body to find statements inside the braces
            std::wstring body = extractBraceBody(statement, tokens);
            // Evaluate condition
            std::wstring cond = extractCondition(statement, tokens);
            // Tokenize condition
            Tokenizer condTok(cond);
            auto condTokens = condTok.tokenize();
            while (evalCondition(condTokens, 0, condTokens.size(), vars)) {
                // Execute body statements
                Tokenizer bodyTok(body);
                auto bodyTokens = bodyTok.tokenize();
                Parser bodyParser(bodyTokens);
                std::vector<std::wstring> bodyStmts;
                if (!bodyParser.parse(bodyStmts)) {
                    result.continueExecution = false;
                    result.exitCode = 2;
                    return result;
                }
                unsigned tmpSleep = 0;
                bool broke = false;
                bool continued = false;
                for (const auto& bs : bodyStmts) {
                    ExecResult br = executeStatement(bs, vars, runCmd, tmpSleep);
                    if (br.breakLoop) { broke = true; break; }
                    if (br.continueLoop) { continued = true; break; }
                    if (!br.continueExecution) {
                        result.exitCode = br.exitCode;
                        result.continueExecution = false;
                        return result;
                    }
                }
                if (broke) break;
                if (continued) continue;
            }
            result.continueExecution = true;
            return result;
        }

        // for VAR = START to END { ... }
        if (first.type == TokenType::For) {
            // Parse: for VAR = START to END { body }
            std::wstring varName, startStr, endStr, body;
            if (!parseForHeader(statement, tokens, varName, startStr, endStr)) {
                writeError(0, L"for: invalid syntax");
                result.continueExecution = true;
                return result;
            }
            body = extractBraceBody(statement, tokens);
            // Strip $ or @ prefix from variable name if present
            if (!varName.empty() && (varName[0] == L'$' || varName[0] == L'@')) {
                varName = varName.substr(1);
            }
            try {
                // Resolve variable references in start/end values
                std::wstring resolvedStart = expandVariables(startStr, vars);
                std::wstring resolvedEnd = expandVariables(endStr, vars);
                double start = std::stod(WideToUtf8(resolvedStart));
                double end = std::stod(WideToUtf8(resolvedEnd));
                for (double i = start; i <= end; ++i) {
                    vars.setNum(varName, i);
                    Tokenizer bodyTok(body);
                    auto bodyTokens = bodyTok.tokenize();
                    Parser bodyParser(bodyTokens);
                    std::vector<std::wstring> bodyStmts;
                    if (!bodyParser.parse(bodyStmts)) {
                        result.continueExecution = false;
                        result.exitCode = 2;
                        return result;
                    }
                    unsigned tmpSleep = 0;
                    bool broke = false;
                    bool continued = false;
                    for (const auto& bs : bodyStmts) {
                        ExecResult br = executeStatement(bs, vars, runCmd, tmpSleep);
                        if (br.breakLoop) { broke = true; break; }
                        if (br.continueLoop) { continued = true; break; }
                        if (!br.continueExecution) {
                            result.exitCode = br.exitCode;
                            result.continueExecution = false;
                            return result;
                        }
                    }
                    if (broke) break;
                    if (continued) continue;
                }
            } catch (...) {
                writeError(0, L"for: invalid range");
                result.continueExecution = true;
                return result;
            }
            result.continueExecution = true;
            return result;
        }

        // if COND { ... } [else { ... }]
        if (first.type == TokenType::If) {
            std::wstring cond = extractCondition(statement, tokens);
            Tokenizer condTok(cond);
            auto condTokens = condTok.tokenize();
            bool condTrue = evalCondition(condTokens, 0, condTokens.size(), vars);
            std::wstring thenBody = extractBraceBody(statement, tokens);
            std::wstring elseBody;
            // Check for else - find "else {" and extract matching body
            size_t elsePos = statement.find(L"else");
            if (elsePos != std::wstring::npos) {
                size_t lbr = statement.find(L'{', elsePos);
                if (lbr != std::wstring::npos) {
                    int depth = 1;
                    bool inString = false;
                    bool escaped = false;
                    size_t i = lbr + 1;
                    while (i < statement.size() && depth > 0) {
                        const wchar_t ch = statement[i];
                        if (inString) {
                            if (escaped) escaped = false;
                            else if (ch == L'\\') escaped = true;
                            else if (ch == L'"') inString = false;
                        } else if (ch == L'"') {
                            inString = true;
                        } else if (ch == L'{') {
                            depth++;
                        } else if (ch == L'}') {
                            depth--;
                            if (depth == 0) {
                                elseBody = statement.substr(lbr + 1, i - lbr - 1);
                                break;
                            }
                        }
                        i++;
                    }
                }
            }
            std::wstring chosenBody = condTrue ? thenBody : elseBody;
            if (!chosenBody.empty()) {
                Tokenizer bodyTok(chosenBody);
                auto bodyTokens = bodyTok.tokenize();
                Parser bodyParser(bodyTokens);
                std::vector<std::wstring> bodyStmts;
                if (!bodyParser.parse(bodyStmts)) {
                    result.continueExecution = false;
                    result.exitCode = 2;
                    return result;
                }
                unsigned tmpSleep = 0;
                for (const auto& bs : bodyStmts) {
                    ExecResult br = executeStatement(bs, vars, runCmd, tmpSleep);
                    if (br.breakLoop || br.continueLoop || !br.continueExecution) {
                        result = br;
                        return result;
                    }
                }
            }
            result.continueExecution = true;
            return result;
        }

        // break
        if (first.type == TokenType::Keyword && first.value == L"break") {
            result.breakLoop = true;
            return result;
        }
        
        // continue
        if (first.type == TokenType::Keyword && first.value == L"continue") {
            result.continueLoop = true;
            return result;
        }
        
        // return [CODE]
        if (first.type == TokenType::Keyword && first.value == L"return") {
            result.exitCode = 0;
            if (tokens.size() > 1 && tokens[1].type == TokenType::Number) {
                try {
                    result.exitCode = std::stoi(WideToUtf8(tokens[1].value));
                } catch (...) {
                    result.exitCode = 0;
                }
            }
            result.continueExecution = false;
            return result;
        }
        
        // CLI command execution: CMD [args...]
        // First token is the command name
        std::wstring cmdName = first.value;
        
        // Build argument list (remaining tokens, excluding =, ;, etc.)
        std::vector<std::wstring> args;
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (tokens[i].type != TokenType::Equals && tokens[i].type != TokenType::Semicolon &&
                tokens[i].type != TokenType::LBrace && tokens[i].type != TokenType::RBrace &&
                tokens[i].type != TokenType::While && tokens[i].type != TokenType::For &&
                tokens[i].type != TokenType::If && tokens[i].type != TokenType::Else &&
                tokens[i].type != TokenType::EndOfFile) {
                args.push_back(expandVariables(tokens[i].value, vars));
            }
        }
        
        if (!cmdName.empty()) {
            // Execute the CLI command
            int exitCode = runCmd(cmdName, args);
            result.exitCode = exitCode;
            result.continueExecution = exitCode != 3; // exit 3 = refused, stop script
            if (result.exitCode == 0) {
                result.description = L"command executed successfully";
            } else {
                result.description = L"command exited with code " + std::to_wstring(exitCode);
            }
        } else {
            writeError(0, L"unknown statement, cannot execute");
            result.continueExecution = true;
            result.exitCode = 1;
        }
        
        return result;
    }
    
    // Expression evaluator with recursive descent parsing
    struct ExprEval {
        const std::vector<Token>& tokens;
        VariableStore& vars;
        size_t pos;

        ExprEval(const std::vector<Token>& t, VariableStore& v) : tokens(t), vars(v), pos(0) {}

        bool evalRange(size_t start, size_t end) {
            pos = start;
            return parseOr(end);
        }

        double evalNumericRange(size_t start, size_t end) {
            pos = start;
            const double value = parseAddSub(end);
            return pos == end ? value : 0.0;
        }

        bool parseOr(size_t end) {
            bool left = parseAnd(end);
            while (pos < end && tokens[pos].type == TokenType::Or) {
                pos++;
                bool right = parseAnd(end);
                left = left || right;
            }
            return left;
        }

        bool parseAnd(size_t end) {
            bool left = parseComparison(end);
            while (pos < end && tokens[pos].type == TokenType::And) {
                pos++;
                bool right = parseComparison(end);
                left = left && right;
            }
            return left;
        }

        bool parseComparison(size_t end) {
            double left = parseUnary(end);
            if (pos < end) {
                TokenType op = tokens[pos].type;
                if (op == TokenType::EqualEqual || op == TokenType::NotEqual ||
                    op == TokenType::LessThan || op == TokenType::GreaterThan ||
                    op == TokenType::LessEqual || op == TokenType::GreaterEqual) {
                    pos++;
                    double right = parseUnary(end);
                    switch (op) {
                        case TokenType::EqualEqual: return left == right;
                        case TokenType::NotEqual: return left != right;
                        case TokenType::LessThan: return left < right;
                        case TokenType::GreaterThan: return left > right;
                        case TokenType::LessEqual: return left <= right;
                        case TokenType::GreaterEqual: return left >= right;
                        default: return false;
                    }
                }
            }
            return left != 0;
        }

        double parseUnary(size_t end) {
            if (pos < end && (tokens[pos].type == TokenType::Bang ||
                              tokens[pos].type == TokenType::Not)) {
                pos++;
                double operand = parseUnary(end);
                return operand == 0 ? 1.0 : 0.0; // !x => x==0
            }
            return parseAddSub(end);
        }

        double parseAddSub(size_t end) {
            double left = parseMulDiv(end);
            while (pos < end && (tokens[pos].type == TokenType::Plus || tokens[pos].type == TokenType::Minus)) {
                TokenType op = tokens[pos].type;
                pos++;
                double right = parseMulDiv(end);
                if (op == TokenType::Plus) left += right;
                else left -= right;
            }
            return left;
        }

        double parseMulDiv(size_t end) {
            double left = parsePrimary(end);
            while (pos < end && (tokens[pos].type == TokenType::Multiply ||
                                 tokens[pos].type == TokenType::Divide ||
                                 tokens[pos].type == TokenType::Modulo)) {
                TokenType op = tokens[pos].type;
                pos++;
                double right = parsePrimary(end);
                switch (op) {
                    case TokenType::Multiply: left *= right; break;
                    case TokenType::Divide: left = right != 0 ? left / right : 0; break;
                    case TokenType::Modulo: left = right != 0 ? std::fmod(left, right) : 0; break;
                    default: break;
                }
            }
            return left;
        }

        double parsePrimary(size_t end) {
            if (pos >= end) return 0;
            if (tokens[pos].type == TokenType::LParen) {
                pos++;
                double val = parseAddSub(end);
                if (pos < end && tokens[pos].type == TokenType::RParen) pos++;
                return val;
            }
            if (tokens[pos].type == TokenType::Number) {
                double val = std::stod(WideToUtf8(tokens[pos].value));
                pos++;
                return val;
            }
            if (tokens[pos].type == TokenType::Identifier) {
                std::wstring val = tokens[pos].value;
                pos++;
                // `$name` / `@name` are the documented variable spellings, but a
                // bare `name` in a condition is what people actually write. It
                // used to fall through to stod("name"), which throws and yields
                // 0 - so `while N < 2` compared 0 < 2 forever and never ended,
                // and `if N == 0` was always true. A bare name that names a
                // variable now reads that variable; anything else keeps the old
                // numeric-literal fallback so nothing that worked changes.
                if (val.size() > 1 && (val[0] == L'$' || val[0] == L'@'))
                    return vars.getNum(val.substr(1));
                if (vars.exists(val)) return vars.getNum(val);
                try { return std::stod(WideToUtf8(val)); } catch (...) { return 0; }
            }
            return 0;
        }
    };

    // Helper: evaluate a boolean condition from tokens
    bool evalCondition(const std::vector<Token>& tokens, size_t start, size_t end, VariableStore& vars) {
        if (start >= end) return false;
        ExprEval evaluator(tokens, vars);
        return evaluator.evalRange(start, end);
    }

    // Helper: parse expression tokens for variable assignment
    std::wstring parseExpressionForExecution(const std::vector<Token>& tokens, size_t startPos, VariableStore& vars) {
        size_t end = startPos;
        while (end < tokens.size() && tokens[end].type != TokenType::Semicolon &&
               tokens[end].type != TokenType::RBrace && tokens[end].type != TokenType::EndOfFile) {
            ++end;
        }
        if (startPos >= end) return L"";

        // Evaluate a numeric expression only when every operand is numeric.
        // This keeps string assignments intact while making loop increments
        // and arithmetic assignments useful at runtime.
        bool numeric = true;
        for (size_t i = startPos; i < end; ++i) {
            const Token& token = tokens[i];
            if (token.type == TokenType::Number || token.type == TokenType::Plus ||
                token.type == TokenType::Minus || token.type == TokenType::Multiply ||
                token.type == TokenType::Divide || token.type == TokenType::Modulo ||
                token.type == TokenType::LParen || token.type == TokenType::RParen) {
                continue;
            }
            if (token.type == TokenType::Identifier) {
                std::wstring name = token.value;
                if (!name.empty() && (name.front() == L'$' || name.front() == L'@')) name.erase(0, 1);
                const std::wstring value = vars.getString(name);
                if (value.empty()) { numeric = false; break; }
                try {
                    size_t consumed = 0;
                    double d = std::stod(WideToUtf8(value), &consumed); (void)d;
                    if (consumed != value.size()) numeric = false;
                } catch (...) { numeric = false; }
                if (!numeric) break;
                continue;
            }
            numeric = false;
            break;
        }
        if (numeric) {
            ExprEval evaluator(tokens, vars);
            return std::to_wstring(evaluator.evalNumericRange(startPos, end));
        }

        std::wstring result;
        for (size_t i = startPos; i < end; ++i) {
            const Token& token = tokens[i];
            if (token.type == TokenType::String) {
                result += token.value;
            } else if (token.type == TokenType::Identifier) {
                std::wstring value = token.value;
                if (value.size() > 1 && (value.front() == L'$' || value.front() == L'@')) {
                    const std::wstring resolved = vars.getString(value.substr(1));
                    result += resolved.empty() ? value : resolved;
                } else {
                    result += value;
                }
            } else {
                result += token.value;
            }
        }
        return result;
    }
    
    // Helper: expand $VAR references in a string
    std::wstring expandVariables(const std::wstring& input, VariableStore& vars) {
        std::wstring result = input;
        // Replace $VAR and @VAR references
        for (int pass = 0; pass < 2; ++pass) {
            wchar_t prefix = (pass == 0) ? L'$' : L'@';
            size_t pos = 0;
            while ((pos = result.find(prefix, pos)) != std::wstring::npos) {
                // Check if it's VAR or ${VAR}
                if (pos + 1 < result.size() && iswalpha(result[pos + 1])) {
                    size_t end = pos + 1;
                    while (end < result.size() && (iswalnum(result[end]) || result[end] == L'_')) {
                        end++;
                    }
                    std::wstring varName = result.substr(pos + 1, end - pos - 1);
                    std::wstring varValue = vars.getString(varName);
                    if (!varValue.empty()) {
                        result.replace(pos, end - pos, varValue);
                        pos += varValue.size();
                    } else {
                        pos += 2; // skip prefix and first char
                    }
                } else {
                    pos++;
                }
            }
        }
        return result;
    }
    
    // -----------------------------------------------------------------------
    // Script execution main function
    // -----------------------------------------------------------------------
    int runScript(const std::wstring& scriptText,
                 std::function<int(const std::wstring&, const std::vector<std::wstring>&)> runCmd,
                 const std::map<std::wstring, std::wstring>& initialVars,
                 bool dryRun,
                 bool trace) {
        clearParseErrors();
        VariableStore vars;
        
        // Initialize with provided variables
        for (const auto& [name, value] : initialVars) {
            vars.define(name, value);
        }
        
        // Tokenize and parse
        Tokenizer tokenizer(scriptText);
        auto tokens = tokenizer.tokenize();
        if (hasParseErrors()) {
            const std::string message = "script: " + WideToUtf8(getFirstParseError()) + "\r\n";
            WriteErr(message);
            return 2;
        }

        // Parse before execution in both normal and dry-run modes. A failed
        // parse must never leave the caller with a partial execution.
        Parser parser(tokens);
        std::vector<std::wstring> parsedStmts;
        if (!parser.parse(parsedStmts)) {
            if (!hasParseErrors()) writeError(0, L"script parse error");
            const std::string message = "script: " + WideToUtf8(getFirstParseError()) + "\r\n";
            WriteErr(message);
            return 2;
        }

        if (dryRun) return 0;
        
        if (trace) {
            WriteOut(WideToUtf8(L"=== Script trace ===\r\n"));
            for (size_t i = 0; i < parsedStmts.size(); ++i) {
                WriteOut(WideToUtf8(std::to_wstring(i + 1) + L": " + parsedStmts[i] + L"\r\n"));
            }
            WriteOut(WideToUtf8(L"=== End script trace ===\r\n"));
        }
        
        // Execute statements
        size_t stmtIdx = 0;
        
        for (;;) {
            if (stmtIdx >= parsedStmts.size()) break;

            if (trace) {
                WriteOut(WideToUtf8(L"> "));
                WriteOut(WideToUtf8(parsedStmts[stmtIdx] + L"\r\n"));
            }

            unsigned unusedSleepAccumulator = 0;
            ExecResult execResult = executeStatement(parsedStmts[stmtIdx], vars, runCmd, unusedSleepAccumulator);

            if (!execResult.continueExecution) {
                return execResult.exitCode;
            }

            stmtIdx++;
        }
        
        return 0;
    }
    
    // -----------------------------------------------------------------------
    // CLI entry point for the script command
    // -----------------------------------------------------------------------
    CommandResult CmdScript(const ScriptOptions& opt) {
        // Read script source
        std::wstring scriptText;
        if (!opt.filePath.empty()) {
            // File content is decoded from UTF-8 below.
        } else if (opt.inlineProvided || !opt.inlineScript.empty()) {
            scriptText = opt.inlineScript;
        } else {
            WriteErr("script: either --file or --script is required\r\n");
            CommandResult r;
            r.exitCode = 2;
            r.err = "script: either --file or --script is required\r\n";
            return r;
        }

        // std::wifstream's encoding follows the active C locale and does not
        // reliably decode UTF-8 script files. Script files are UTF-8 by
        // default (with an optional UTF-8 BOM); decode explicitly so Windows
        // behavior is deterministic.
        if (!opt.filePath.empty()) {
            std::ifstream file(opt.filePath, std::ios::binary);
            if (!file.is_open()) {
                WriteErr("script: cannot open file '" + WideToUtf8(opt.filePath) + "'\r\n");
                CommandResult r;
                r.exitCode = 2;
                r.err = "script: cannot open file '" + WideToUtf8(opt.filePath) + "'\r\n";
                return r;
            }
            std::string bytes((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
            if (bytes.size() >= 3 &&
                static_cast<unsigned char>(bytes[0]) == 0xEF &&
                static_cast<unsigned char>(bytes[1]) == 0xBB &&
                static_cast<unsigned char>(bytes[2]) == 0xBF) {
                bytes.erase(0, 3);
            }
            scriptText.clear();
            for (size_t i = 0; i < bytes.size();) {
                const unsigned char first = static_cast<unsigned char>(bytes[i]);
                uint32_t codepoint = 0;
                size_t continuationCount = 0;
                if (first < 0x80) {
                    codepoint = first;
                } else if ((first & 0xE0) == 0xC0 && first >= 0xC2) {
                    codepoint = first & 0x1F;
                    continuationCount = 1;
                } else if ((first & 0xF0) == 0xE0) {
                    codepoint = first & 0x0F;
                    continuationCount = 2;
                } else if ((first & 0xF8) == 0xF0) {
                    codepoint = first & 0x07;
                    continuationCount = 3;
                } else {
                    WriteErr("script: invalid UTF-8 in file '" + WideToUtf8(opt.filePath) + "'\r\n");
                    CommandResult r;
                    r.exitCode = 2;
                    r.err = "script: invalid UTF-8 in file '" + WideToUtf8(opt.filePath) + "'\r\n";
                    return r;
                }
                if (i + continuationCount >= bytes.size()) {
                    WriteErr("script: invalid UTF-8 in file '" + WideToUtf8(opt.filePath) + "'\r\n");
                    CommandResult r;
                    r.exitCode = 2;
                    r.err = "script: invalid UTF-8 in file '" + WideToUtf8(opt.filePath) + "'\r\n";
                    return r;
                }
                for (size_t j = 1; j <= continuationCount; ++j) {
                    const unsigned char next = static_cast<unsigned char>(bytes[i + j]);
                    if ((next & 0xC0) != 0x80) {
                        WriteErr("script: invalid UTF-8 in file '" + WideToUtf8(opt.filePath) + "'\r\n");
                        CommandResult r;
                        r.exitCode = 2;
                        r.err = "script: invalid UTF-8 in file '" + WideToUtf8(opt.filePath) + "'\r\n";
                        return r;
                    }
                    codepoint = (codepoint << 6) | (next & 0x3F);
                }
                if ((continuationCount == 1 && codepoint < 0x80) ||
                    (continuationCount == 2 && codepoint < 0x800) ||
                    (continuationCount == 3 && codepoint < 0x10000) ||
                    codepoint > 0x10FFFF ||
                    (first == 0xE0 && static_cast<unsigned char>(bytes[i + 1]) < 0xA0) ||
                    (first == 0xED && static_cast<unsigned char>(bytes[i + 1]) >= 0xA0) ||
                    (first == 0xF0 && static_cast<unsigned char>(bytes[i + 1]) < 0x90) ||
                    (first == 0xF4 && static_cast<unsigned char>(bytes[i + 1]) >= 0x90) ||
                    first > 0xF4 ||
                    (codepoint >= 0xD800 && codepoint <= 0xDFFF)) {
                    WriteErr("script: invalid UTF-8 in file '" + WideToUtf8(opt.filePath) + "'\r\n");
                    CommandResult r;
                    r.exitCode = 2;
                    r.err = "script: invalid UTF-8 in file '" + WideToUtf8(opt.filePath) + "'\r\n";
                    return r;
                }
                if constexpr (sizeof(wchar_t) == 2) {
                    if (codepoint > 0xFFFF) {
                        codepoint -= 0x10000;
                        scriptText += static_cast<wchar_t>(0xD800 + (codepoint >> 10));
                        scriptText += static_cast<wchar_t>(0xDC00 + (codepoint & 0x3FF));
                    } else {
                        scriptText += static_cast<wchar_t>(codepoint);
                    }
                } else {
                    scriptText += static_cast<wchar_t>(codepoint);
                }
                i += continuationCount + 1;
            }
        }

        // Run the script
        // The runCmd function executes CLI commands by constructing argv
        // and calling RunCliCommand.
        auto runCmd = [&](const std::wstring& cmd, const std::vector<std::wstring>& args) -> int {
            // Build argv for RunCli: [0]=exe, [1]=cmd, [2..]=args
            std::vector<const wchar_t*> argv;
            argv.push_back(L"wintcp.exe");
            argv.push_back(cmd.c_str());
            for (const auto& arg : args) {
                argv.push_back(arg.c_str());
            }
            argv.push_back(nullptr);
            return RunCliCommand(static_cast<int>(argv.size()) - 1, const_cast<wchar_t**>(argv.data()));
        };

        int rc = runScript(scriptText, runCmd, opt.initialVars, opt.dryRun, opt.trace);

        CommandResult r;
        r.exitCode = rc;
        return r;
    }

}  // namespace Script
}  // namespace wintcp
