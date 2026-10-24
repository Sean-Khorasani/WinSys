// RestrictionModel.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <string>

namespace wintcp {

enum class RestrictionProtocol { TcpAndUdp, Tcp, Udp };

// Reviewed scope for an optional, elevated, temporary WFP restriction.
// This is data only; constructing or validating it never installs a filter.
struct RestrictionPlan {
    std::string imagePath;
    std::string userSid;
    std::string imageFileIdentity;  // Broker-resolved file ID/version approved at preview.
    std::string remoteAddress;  // Empty = every destination, otherwise literal IP.
    std::uint16_t remotePort = 0;  // Zero = every port.
    RestrictionProtocol protocol = RestrictionProtocol::TcpAndUdp;
    unsigned durationSeconds = 900;
};

bool ValidateRestrictionPlan(const RestrictionPlan& plan, std::string* error);
std::string RestrictionPlanHash(const RestrictionPlan& plan);

// Expiry uses whichever deadline comes first. A backward wall-clock jump
// cannot extend the monotonic duration budget.
bool RestrictionExpired(std::uint64_t startMonotonicMs,
                        std::uint64_t deadlineUtcMs,
                        std::uint64_t nowMonotonicMs,
                        std::uint64_t nowUtcMs,
                        unsigned durationSeconds);

}  // namespace wintcp
