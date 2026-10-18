// WebUi.h
// SPDX-License-Identifier: Apache-2.0
// Loopback-only browser interface entry point.
#pragma once

#include <cstdint>
#include <string>

namespace wintcp {

int RunWebUiServer();

// JSON emitters, exposed so the unit tests can assert their output shape
// directly. These were file-local before; ParseUint64Strict in particular is
// the fix for a query-string parameter that used to throw an escaping exception
// and terminate the server, which is exactly the kind of bug a test must pin.
std::string JsonNumber(double value);
std::string JsonQuote(const std::string& text);
bool ParseUint64Strict(const std::string& text, uint64_t* out);

}  // namespace wintcp
