// RestrictionWfp.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "RestrictionModel.h"
#include "RestrictionLease.h"

namespace wintcp {

// Read-only check used both before issuing an approval and immediately before
// installation. Never treats a missing/reparse/system executable as reviewed.
bool ReviewRestrictionTarget(const RestrictionPlan& plan, std::string* error,
                             std::string* fileIdentity = nullptr,
                             HANDLE* lockedFile = nullptr);

// Broker-only WFP primitive. No ordinary CLI, GUI, or HTTP route calls this.
// The dynamic session owns every provider, sublayer, and filter added here;
// closing/crashing the broker removes all of them instead of persisting rules.
class DynamicWfpSession {
public:
    DynamicWfpSession() = default;
    ~DynamicWfpSession();
    DynamicWfpSession(const DynamicWfpSession&) = delete;
    DynamicWfpSession& operator=(const DynamicWfpSession&) = delete;

    bool Open(std::string* error);
    bool Apply(const RestrictionPlan& plan, std::vector<std::uint64_t>* filterIds,
               std::string* error);
    bool Release(const std::vector<std::uint64_t>& filterIds,
                 std::string* error);
    void Close();
    bool IsOpen() const { return engine_ != nullptr; }

private:
    HANDLE engine_ = nullptr;
    GUID providerKey_ = {};
    GUID subLayerKey_ = {};
    std::set<std::uint64_t> owned_;
};

// Thin broker adapter; the controller owns lease policy and this object owns
// only the dynamic WFP session. Neither is reachable from ordinary UI routes.
class DynamicWfpBackend final : public RestrictionFilterBackend {
public:
    bool Open(std::string* error) { return session_.Open(error); }
    bool Install(const RestrictionPlan& plan, std::vector<std::uint64_t>* ids,
                 std::string* error) override;
    bool Remove(const std::vector<std::uint64_t>& ids,
                std::string* error) override;
    void Close() override { session_.Close(); }

private:
    DynamicWfpSession session_;
};

}  // namespace wintcp
