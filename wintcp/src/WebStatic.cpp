// WebStatic.cpp
// SPDX-License-Identifier: Apache-2.0
// Safe static file handler implementation.

#include "WebStatic.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace wintcp {
namespace {

// Allowed prefixes (must start with /)
const std::vector<std::string> kAllowedPrefixes = {
    "/js/", "/css/", "/vendor/", "/fonts/", "/data/", "/img/",
};

// Allowed extensions
const std::vector<std::string> kAllowedExtensions = {
    ".js", ".mjs", ".css", ".json", ".svg", ".woff2", ".png", ".ico", ".txt",
};

// Reserved Windows device names
const char* kReservedNames[] = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
};

bool IsReservedName(const std::string& name) {
    std::string upper;
    for (char c : name) upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    // Strip extension
    size_t dot = upper.find('.');
    if (dot != std::string::npos) upper = upper.substr(0, dot);
    for (const char* reserved : kReservedNames) {
        if (upper == reserved) return true;
    }
    return false;
}

bool IsAllowedExtension(const std::string& path) {
    size_t dot = path.rfind('.');
    if (dot == std::string::npos) return false;
    std::string ext = path.substr(dot);
    for (char& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (const auto& allowed : kAllowedExtensions) {
        if (ext == allowed) return true;
    }
    return false;
}

bool IsAllowedPrefix(const std::string& path) {
    for (const auto& prefix : kAllowedPrefixes) {
        if (path.rfind(prefix, 0) == 0) return true;
    }
    return false;
}

}  // namespace

bool IsSafeStaticPath(const std::string& path) {
    if (path.empty() || path[0] != '/') return false;
    if (!IsAllowedPrefix(path)) return false;
    if (!IsAllowedExtension(path)) return false;

    // Reject path traversal
    if (path.find("..") != std::string::npos) return false;
    // Reject backslash (Windows path separator)
    if (path.find('\\') != std::string::npos) return false;
    // Reject drive letters and alternate data streams
    if (path.find(':') != std::string::npos) return false;
    // Reject null bytes
    if (path.find('\0') != std::string::npos) return false;

    // Check each path component for reserved names and trailing dots/spaces
    size_t start = 1;
    while (start < path.size()) {
        size_t end = path.find('/', start);
        if (end == std::string::npos) end = path.size();
        std::string component = path.substr(start, end - start);
        if (component.empty() || component == ".") { start = end + 1; continue; }
        if (IsReservedName(component)) return false;
        if (!component.empty() && (component.back() == '.' || component.back() == ' ')) return false;
        start = end + 1;
    }

    return true;
}

const char* StaticMimeType(const std::string& ext) {
    if (ext == ".js" || ext == ".mjs") return "text/javascript; charset=utf-8";
    if (ext == ".css") return "text/css; charset=utf-8";
    if (ext == ".json") return "application/json; charset=utf-8";
    if (ext == ".svg") return "image/svg+xml";
    if (ext == ".png") return "image/png";
    if (ext == ".ico") return "image/x-icon";
    if (ext == ".woff2") return "font/woff2";
    if (ext == ".txt") return "text/plain; charset=utf-8";
    return "application/octet-stream";
}

const std::vector<std::string>& StaticAllowedPrefixes() {
    return kAllowedPrefixes;
}

const std::vector<std::string>& StaticAllowedExtensions() {
    return kAllowedExtensions;
}

}  // namespace wintcp
