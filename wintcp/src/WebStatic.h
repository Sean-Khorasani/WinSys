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

// True when the path falls under a static prefix but is NOT safe to serve (a
// traversal attempt, a reserved device name, a disallowed extension). The route
// uses this to answer 403 rather than 404, so a probe cannot tell "no such
// asset" from "that asset is forbidden" - and, more usefully, so a traversal
// attempt is still recorded as a rejection.
bool IsRejectedStaticPath(const std::string& path);

// Get the MIME type for a file extension.
const char* StaticMimeType(const std::string& ext);

// Get the maximum file size for a given path.
size_t StaticMaxBytesFor(const std::string& path);

// List of allowed static file prefixes.
const std::vector<std::string>& StaticAllowedPrefixes();

// List of allowed static file extensions.
const std::vector<std::string>& StaticAllowedExtensions();

}  // namespace wintcp
