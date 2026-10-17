// Notify.h
// SPDX-License-Identifier: Apache-2.0
// Webhook integration: POST WinTCP state to an HTTP endpoint (Slack, Discord,
// a SIEM, a custom receiver).
//
// Two halves with a deliberate split:
//   * BuildStatePayload is PURE - it renders JSON from plain values and is
//     unit-tested like every other formatter in this codebase.
//   * PostWebhook is the only side effect - one bounded HTTP POST that never
//     throws and never crashes a monitor, it just reports success or failure.
#pragma once

#include <string>

namespace wintcp {

// Build the JSON body for a state ping. Pure; unit-tested. `timeStamp` is a
// UTC ISO-8601 string; the counts come from the current snapshot.
std::string BuildStatePayload(const std::string& timeStamp, size_t connections,
                              size_t tcp, size_t udp, size_t established);

// UTC ISO-8601 wall clock, e.g. "2026-10-16T22:47:27.861Z". Exposed so the
// CLI verb and the webhook share one timestamp source.
std::string UtcIso8601();

// POST a JSON body to a webhook URL. Returns true when the endpoint answered
// 2xx. Bounded by an internal timeout, tolerates a refused/unreachable host,
// and reports failure to the caller rather than crashing a monitor. http and
// https both work (WinHTTP). `body` is UTF-8 JSON and is sent as-is.
bool PostWebhook(const std::wstring& url, const std::string& body);

}  // namespace wintcp
