// WebStatic.h
// SPDX-License-Identifier: Apache-2.0
// Safe static file handler for the Web UI. Allow-list of prefixes and
// extensions, path traversal protection, per-file size cap.
//
// SECURITY: This is the only handler that serves files from disk. It must
// never serve anything outside the webui root, and must reject path
// traversal attempts, alternate data streams, and reparse points.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <string>
#include <vector>

namespace wintcp {

// Validate a URL path for static file serving.
// Returns true if the path is safe to serve.
bool IsSafeStaticPath(const std::string& path);

// Get the MIME type for a file extension.
const char* StaticMimeType(const std::string& ext);

// List of allowed static file prefixes.
const std::vector<std::string>& StaticAllowedPrefixes();

// List of allowed static file extensions.
const std::vector<std::string>& StaticAllowedExtensions();

}  // namespace wintcp
