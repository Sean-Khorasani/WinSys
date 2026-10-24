// RestrictionModel.cpp
// SPDX-License-Identifier: Apache-2.0
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sddl.h>

#include "RestrictionModel.h"
#include "Sha256.h"

#include <limits>

namespace wintcp {
namespace {

bool WideUtf8(const std::string& input, std::wstring* output) {
    if (input.empty() || input.size() > 1024 || output == nullptr) return false;
    const int length = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (length <= 0) return false;
    output->resize(static_cast<std::size_t>(length));
    return ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        input.data(), static_cast<int>(input.size()), &(*output)[0], length) == length;
}

std::string Field(const std::string& value) {
    return std::to_string(value.size()) + ':' + value;
}

}  // namespace

bool ValidateRestrictionPlan(const RestrictionPlan& plan, std::string* error) {
    if (error == nullptr) return false;
    const auto fail = [error](const char* code) { *error = code; return false; };
    if (plan.durationSeconds < 60 || plan.durationSeconds > 86400)
        return fail("invalid_duration");
    if (plan.protocol != RestrictionProtocol::TcpAndUdp &&
        plan.protocol != RestrictionProtocol::Tcp &&
        plan.protocol != RestrictionProtocol::Udp)
        return fail("invalid_protocol");
    if (plan.imageFileIdentity.size() > 160 ||
        plan.imageFileIdentity.find_first_not_of("0123456789:") != std::string::npos)
        return fail("invalid_file_identity");
    std::wstring path;
    if (!WideUtf8(plan.imagePath, &path) || path.size() < 4 ||
        !((path[0] >= L'A' && path[0] <= L'Z') ||
          (path[0] >= L'a' && path[0] <= L'z')) ||
        path[1] != L':' || path[2] != L'\\')
        return fail("invalid_image_path");
    for (wchar_t c : path)
        if (c < L' ' || c == L'/' || c == L'|' || c == L'"')
            return fail("invalid_image_path");
    std::wstring canonical(32768, L'\0');
    const DWORD length = ::GetFullPathNameW(path.c_str(),
        static_cast<DWORD>(canonical.size()), &canonical[0], nullptr);
    if (length == 0 || length >= canonical.size())
        return fail("invalid_image_path");
    canonical.resize(length);
    if (::CompareStringOrdinal(path.c_str(), static_cast<int>(path.size()),
        canonical.c_str(), static_cast<int>(canonical.size()), TRUE) != CSTR_EQUAL)
        return fail("image_path_not_canonical");
    std::wstring sid;
    if (!WideUtf8(plan.userSid, &sid)) return fail("invalid_user_sid");
    PSID parsed = nullptr;
    const bool validSid = ::ConvertStringSidToSidW(sid.c_str(), &parsed) != FALSE &&
        parsed != nullptr && ::IsValidSid(parsed) != FALSE;
    if (parsed != nullptr) ::LocalFree(parsed);
    if (!validSid) return fail("invalid_user_sid");
    if (plan.remoteAddress.empty()) {
        if (plan.remotePort != 0) return fail("port_requires_peer");
    } else {
        if (plan.remoteAddress.size() > 45 ||
            plan.remoteAddress.find_first_not_of("0123456789abcdefABCDEF:.") !=
                std::string::npos)
            return fail("peer_must_be_literal_ip");
        IN_ADDR ipv4 = {};
        IN6_ADDR ipv6 = {};
        if (::InetPtonA(AF_INET, plan.remoteAddress.c_str(), &ipv4) != 1 &&
            ::InetPtonA(AF_INET6, plan.remoteAddress.c_str(), &ipv6) != 1)
            return fail("peer_must_be_literal_ip");
    }
    error->clear();
    return true;
}

std::string RestrictionPlanHash(const RestrictionPlan& plan) {
    const std::string canonical = "WinTCP-Restriction-Plan:1\n" +
        Field(plan.imagePath) + Field(plan.userSid) + Field(plan.imageFileIdentity) +
        Field(plan.remoteAddress) +
        std::to_string(plan.remotePort) + ':' +
        std::to_string(static_cast<unsigned>(plan.protocol)) + ':' +
        std::to_string(plan.durationSeconds);
    return Sha256HexA(Sha256Bytes(
        reinterpret_cast<const unsigned char*>(canonical.data()),
        canonical.size()));
}

bool RestrictionExpired(std::uint64_t startMonotonicMs,
                        std::uint64_t deadlineUtcMs,
                        std::uint64_t nowMonotonicMs,
                        std::uint64_t nowUtcMs,
                        unsigned durationSeconds) {
    if (nowUtcMs >= deadlineUtcMs) return true;
    if (nowMonotonicMs < startMonotonicMs) return true;
    const std::uint64_t budgetMs =
        static_cast<std::uint64_t>(durationSeconds) * 1000ULL;
    return nowMonotonicMs - startMonotonicMs >= budgetMs;
}

}  // namespace wintcp
