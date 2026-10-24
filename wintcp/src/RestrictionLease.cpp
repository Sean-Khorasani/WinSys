// RestrictionLease.cpp
// SPDX-License-Identifier: Apache-2.0
#include "RestrictionLease.h"

#include <limits>
#include <utility>

namespace wintcp {

RestrictionLeaseController::RestrictionLeaseController(RestrictionFilterBackend* backend)
    : backend_(backend) {}

RestrictionLeaseController::~RestrictionLeaseController() { ReleaseAll("broker_exit"); }

void RestrictionLeaseController::Record(const RestrictionLease& lease,
                                        const std::string& state,
                                        const std::string& reason,
                                        RestrictionNow now) {
    if (changes_.size() >= 1024) changes_.pop_front();
    changes_.push_back({++nextChange_, lease, state, reason, now});
}

bool RestrictionLeaseController::Preview(const RestrictionPlan& plan,
                                         const std::string& token,
                                         RestrictionNow now,
                                         std::string* error) {
    if (error == nullptr) return false;
    if (backend_ == nullptr || token.empty() || token.size() > 128 ||
        approvals_.count(token) != 0 || approvals_.size() >= 128) {
        *error = "approval_unavailable";
        return false;
    }
    if (!ValidateRestrictionPlan(plan, error)) return false;
    approvals_.emplace(token, Approval{RestrictionPlanHash(plan), plan, now});
    error->clear();
    return true;
}

bool RestrictionLeaseController::Apply(const RestrictionPlan& plan,
                                       const std::string& token,
                                       const std::string& leaseId,
                                       const std::string& owner,
                                       RestrictionNow now,
                                       std::string* error) {
    if (error == nullptr) return false;
    const auto approval = approvals_.find(token);
    if (approval == approvals_.end()) { *error = "approval_missing"; return false; }
    const Approval granted = approval->second;
    approvals_.erase(approval);
    if (backend_ == nullptr || leaseId.empty() || leaseId.size() > 128 ||
        owner.empty() || owner.size() > 128 || active_.count(leaseId) != 0 ||
        active_.size() >= 128) {
        *error = "lease_unavailable";
        return false;
    }
    if (!heartbeatSeen_ || now.monotonicMs < heartbeat_.monotonicMs ||
        now.monotonicMs - heartbeat_.monotonicMs >= 10000) {
        *error = "engine_heartbeat_missing";
        return false;
    }
    if (!ValidateRestrictionPlan(plan, error)) return false;
    const std::string hash = RestrictionPlanHash(plan);
    if (granted.hash != hash || now.monotonicMs < granted.issued.monotonicMs ||
        now.monotonicMs - granted.issued.monotonicMs > 30000 ||
        now.utcMs < granted.issued.utcMs ||
        now.utcMs - granted.issued.utcMs > 30000) {
        *error = "approval_expired_or_changed";
        return false;
    }
    const std::uint64_t durationMs =
        static_cast<std::uint64_t>(plan.durationSeconds) * 1000ULL;
    if (now.utcMs > std::numeric_limits<std::uint64_t>::max() - durationMs) {
        *error = "clock_out_of_range";
        return false;
    }
    while (!creationTimes_.empty() && now.monotonicMs >= creationTimes_.front() &&
           now.monotonicMs - creationTimes_.front() >= 60000)
        creationTimes_.pop_front();
    if (creationTimes_.size() >= 32 ||
        (!creationTimes_.empty() && now.monotonicMs < creationTimes_.back())) {
        *error = "restriction_creation_rate_limited";
        return false;
    }
    creationTimes_.push_back(now.monotonicMs);
    RestrictionLease lease;
    lease.id = leaseId;
    lease.owner = owner;
    lease.planHash = hash;
    lease.plan = plan;
    lease.started = now;
    lease.deadlineUtcMs = now.utcMs + durationMs;
    std::vector<std::uint64_t> ids;
    if (!backend_->Install(plan, &ids, error) || ids.empty() || ids.size() > 4) {
        if (error->empty()) *error = "filter_install_failed";
        // Install is transactional, but close also covers uncertain failures.
        ReleaseAll("install_failure_cleanup", now);
        Record(lease, "failed", *error, now);
        return false;
    }
    lease.filterIds = std::move(ids);
    Record(lease, "active", "filters_verified", now);
    active_.emplace(leaseId, std::move(lease));
    error->clear();
    return true;
}

bool RestrictionLeaseController::ApplyApproved(const std::string& token,
                                               const std::string& leaseId,
                                               const std::string& owner,
                                               RestrictionNow now,
                                               std::string* error) {
    if (error == nullptr) return false;
    const auto approval = approvals_.find(token);
    if (approval == approvals_.end()) {
        *error = "approval_missing";
        return false;
    }
    const RestrictionPlan plan = approval->second.plan;
    return Apply(plan, token, leaseId, owner, now, error);
}

bool RestrictionLeaseController::Release(const std::string& leaseId,
                                         std::string* error, RestrictionNow now) {
    if (error == nullptr) return false;
    const auto lease = active_.find(leaseId);
    if (lease == active_.end()) { *error = "lease_not_found"; return false; }
    if (backend_ == nullptr || !backend_->Remove(lease->second.filterIds, error)) {
        if (error->empty()) *error = "filter_release_failed";
        ReleaseAll("release_failure_cleanup", now);
        return false;
    }
    Record(lease->second, "released", "manual_release", now);
    active_.erase(lease);
    error->clear();
    return true;
}

void RestrictionLeaseController::Sweep(RestrictionNow now) {
    for (auto it = approvals_.begin(); it != approvals_.end();) {
        if (now.monotonicMs < it->second.issued.monotonicMs ||
            now.monotonicMs - it->second.issued.monotonicMs > 30000 ||
            now.utcMs < it->second.issued.utcMs ||
            now.utcMs - it->second.issued.utcMs > 30000)
            it = approvals_.erase(it);
        else ++it;
    }
    if (heartbeatSeen_ &&
        (now.monotonicMs < heartbeat_.monotonicMs ||
         now.monotonicMs - heartbeat_.monotonicMs >= 10000)) {
        ReleaseAll("engine_heartbeat_lost", now);
        return;
    }
    for (auto it = active_.begin(); it != active_.end();) {
        if (!RestrictionExpired(it->second.started.monotonicMs,
                                it->second.deadlineUtcMs,
                                now.monotonicMs, now.utcMs,
                                it->second.plan.durationSeconds)) {
            ++it;
            continue;
        }
        std::string error;
        if (backend_ == nullptr ||
            !backend_->Remove(it->second.filterIds, &error)) {
            ReleaseAll("expiry_failure_cleanup", now);
            return;
        }
        Record(it->second, "expired", "deadline_reached", now);
        it = active_.erase(it);
    }
}

void RestrictionLeaseController::Heartbeat(RestrictionNow now) {
    heartbeat_ = now;
    heartbeatSeen_ = true;
}

bool RestrictionLeaseController::HeartbeatCurrent(RestrictionNow now) const {
    return heartbeatSeen_ && now.monotonicMs >= heartbeat_.monotonicMs &&
        now.monotonicMs - heartbeat_.monotonicMs < 10000;
}

void RestrictionLeaseController::ReleaseAll(const std::string& reason,
                                           RestrictionNow now) {
    approvals_.clear();
    if (backend_ != nullptr) backend_->Close();
    for (const auto& pair : active_)
        Record(pair.second, reason == "broker_exit" ? "ended_by_broker_exit" : "released",
               reason, now);
    active_.clear();
    heartbeatSeen_ = false;
}

}  // namespace wintcp
