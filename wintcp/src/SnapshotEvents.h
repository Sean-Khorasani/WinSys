// SnapshotEvents.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "Connection.h"
#include "NetworkEvents.h"

namespace wintcp {

// Single-owner adapter. It only reports table observations and disappearances;
// it cannot establish attempts, failures, denials, or a UDP handshake.
class SnapshotEventAdapter {
public:
    explicit SnapshotEventAdapter(std::string epoch);
    std::vector<NetworkEvent> Observe(const std::vector<Connection>& rows,
                                      const std::string& utc,
                                      std::uint64_t monotonicNs);
    void Reset();

private:
    std::string epoch_;
    std::uint64_t sequence_ = 0;
    std::uint64_t flowSequence_ = 0;
    bool baseline_ = false;
    std::map<std::string, NetworkEvent> previous_;
};

}  // namespace wintcp
