// Notify.cpp
// SPDX-License-Identifier: Apache-2.0
// See Notify.h. The payload builder is pure; PostWebhook is the one side effect.

#include "Notify.h"

// Bound winhttp.lib to THIS translation unit. The build lists every library
// explicitly in its link lines, but a source that owns an external dependency
// declaring it here keeps the dependency next to the code that needs it and
// means the new file joins the build paths WITHOUT a second edit per path.
#pragma comment(lib, "winhttp.lib")

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>   // winhttp.h needs HANDLE/INTERNET_PORT from this
#include <winhttp.h>

#include <cstdio>
#include <string>

namespace wintcp {
namespace {

std::string JsonEscapeA(const std::string& s) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out += hex[c >> 4];
                    out += hex[c & 0x0f];
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

}  // namespace

std::string UtcIso8601() {
    SYSTEMTIME t = {};
    ::GetSystemTime(&t);
    char out[40] = {};
    (void)::sprintf_s(out, sizeof(out), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                      t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond,
                      t.wMilliseconds);
    return out;
}

std::string BuildStatePayload(const std::string& timeStamp, size_t connections,
                              size_t tcp, size_t udp, size_t established) {
    std::string out = "{\"time\":\"";
    out += JsonEscapeA(timeStamp);
    out += "\",\"source\":\"wintcp\",\"connections\":";
    out += std::to_string(connections);
    out += ",\"tcp\":";
    out += std::to_string(tcp);
    out += ",\"udp\":";
    out += std::to_string(udp);
    out += ",\"established\":";
    out += std::to_string(established);
    out += "}";
    return out;
}

bool PostWebhook(const std::wstring& url, const std::string& body) {
    if (url.empty() || body.empty()) return false;
    URL_COMPONENTS comp = {};
    comp.dwStructSize = sizeof(comp);
    comp.dwSchemeLength = (DWORD)-1;
    comp.dwHostNameLength = (DWORD)-1;
    comp.dwUrlPathLength = (DWORD)-1;
    comp.dwExtraInfoLength = (DWORD)-1;
    if (!::WinHttpCrackUrl(url.c_str(), 0, 0, &comp)) return false;

    std::wstring scheme(comp.lpszScheme, comp.dwSchemeLength);
    std::wstring host(comp.lpszHostName, comp.dwHostNameLength);
    std::wstring path(comp.lpszUrlPath, comp.dwUrlPathLength);
    if (host.empty()) return false;
    if (path.empty()) path = L"/";

    const bool https =
        (scheme.size() == 5 && _wcsnicmp(scheme.c_str(), L"https", 5) == 0);
    const INTERNET_PORT port = comp.nPort != 0
        ? comp.nPort
        : (https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT);

    HINTERNET session = ::WinHttpOpen(L"WinTCP/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == nullptr) return false;
    // Bound every phase so an unreachable host cannot hang the caller (a
    // monitor, the GUI, or a one-shot CLI). resolve=0 = system default;
    // connect/send/receive are milliseconds. Without this the OS default
    // (~20s+ per phase) turns a dead webhook into a stall.
    (void)::WinHttpSetTimeouts(session, 0, 5000, 5000, 10000);
    HINTERNET connect = ::WinHttpConnect(session, host.c_str(), port, 0);
    if (connect == nullptr) { ::WinHttpCloseHandle(session); return false; }
    HINTERNET request = ::WinHttpOpenRequest(connect, L"POST", path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        https ? WINHTTP_FLAG_SECURE : 0);
    if (request == nullptr) {
        ::WinHttpCloseHandle(connect);
        ::WinHttpCloseHandle(session);
        return false;
    }

    // A webhook reply is small; drop it after reading the status so the handle
    // closes cleanly without holding a socket open.
    BOOL sent = FALSE;
    const wchar_t* headers = L"Content-Type: application/json\r\n";
    sent = ::WinHttpSendRequest(request, headers, (DWORD)-1,
        const_cast<char*>(body.data()), (DWORD)body.size(),
        (DWORD)body.size(), 0);
    if (sent) sent = ::WinHttpReceiveResponse(request, nullptr);

    bool ok = false;
    if (sent) {
        DWORD status = 0, size = sizeof(status);
        if (::WinHttpQueryHeaders(request,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &size,
                WINHTTP_NO_HEADER_INDEX)) {
            ok = (status >= 200 && status < 300);
        }
    }
    ::WinHttpCloseHandle(request);
    ::WinHttpCloseHandle(connect);
    ::WinHttpCloseHandle(session);
    return ok;
}

}  // namespace wintcp
