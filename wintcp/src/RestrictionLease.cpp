// RestrictionLease.cpp
// SPDX-License-Identifier: Apache-2.0
#include "RestrictionLease.h"

#include <algorithm>
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
                                         const std::string& owner,
                                         RestrictionNow now,
                                         std::string* error) {
    if (error == nullptr) return false;
    if (backend_ == nullptr || token.empty() || token.size() > 128 ||
        owner.empty() || owner.size() > 128 ||
        approvals_.count(token) != 0 || approvals_.size() >= 128) {
        *error = "approval_unavailable";
        return false;
    }
    for (const auto& pair : active_) {
        if (owner.rfind("recipe:", 0) == 0 && pair.second.owner == owner) {
            *error = "owner_already_armed";
            return false;
        }
    }
    for (const auto& pair : approvals_) {
        if (owner.rfind("recipe:", 0) == 0 && pair.second.owner == owner) {
            *error = "owner_approval_pending";
            return false;
        }
    }
    if (!ValidateRestrictionPlan(plan, error)) return false;
    approvals_.emplace(token, Approval{RestrictionPlanHash(plan), owner, plan, now});
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
    if (owner != granted.owner) {
        *error = "approval_owner_changed";
        return false;
    }
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
                                               RestrictionNow now,
                                               std::string* error) {
    if (error == nullptr) return false;
    const auto approval = approvals_.find(token);
    if (approval == approvals_.end()) {
        *error = "approval_missing";
        return false;
    }
    const RestrictionPlan plan = approval->second.plan;
    const std::string owner = approval->second.owner;
    return Apply(plan, token, leaseId, owner, now, error);
}

bool RestrictionLeaseController::ArmRecipeAction(
    const std::string& owner, std::uint64_t recipeRevision,
    const RestrictionPlan& approvedScope,
    unsigned grantLifetimeSeconds, unsigned leaseDurationSeconds,
    unsigned maxActions, unsigned maxCumulativeDurationSeconds,
    RestrictionNow now, std::string* error) {
    if (error == nullptr) return false;
    bool ownerValid = owner.rfind("recipe:", 0) == 0 &&
        owner.size() > 7 && owner.size() <= 39;
    for (std::size_t i = 7; ownerValid && i < owner.size(); ++i) {
        const char c = owner[i];
        ownerValid = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_';
    }
    const bool ownerActive = std::any_of(active_.begin(), active_.end(),
        [&owner](const auto& item) { return item.second.owner == owner; });
    if (backend_ == nullptr || !ownerValid || recipeRevision == 0 || ownerActive ||
        recipeGrants_.size() >= 128 ||
        grantLifetimeSeconds == 0 || grantLifetimeSeconds > 8 * 60 * 60 ||
        leaseDurationSeconds < 60 || leaseDurationSeconds > 8 * 60 * 60 ||
        maxActions == 0 || maxActions > 3 ||
        maxCumulativeDurationSeconds < leaseDurationSeconds ||
        maxCumulativeDurationSeconds > 60 * 60 ||
        leaseDurationSeconds > maxCumulativeDurationSeconds) {
        *error = "active_grant_scope_invalid";
        return false;
    }
    if (!heartbeatSeen_ || now.monotonicMs < heartbeat_.monotonicMs ||
        now.monotonicMs - heartbeat_.monotonicMs >= 10000) {
        *error = "engine_heartbeat_missing";
        return false;
    }
    if (recipeGrants_.count(owner) != 0) {
        *error = "owner_already_armed";
        return false;
    }
    RestrictionPlan scope = approvedScope;
    scope.durationSeconds = leaseDurationSeconds;
    if (!ValidateRestrictionPlan(scope, error)) return false;
    const std::uint64_t lifetimeMs =
        static_cast<std::uint64_t>(grantLifetimeSeconds) * 1000ULL;
    if (now.utcMs > std::numeric_limits<std::uint64_t>::max() - lifetimeMs ||
        now.monotonicMs > std::numeric_limits<std::uint64_t>::max() - lifetimeMs) {
        *error = "clock_out_of_range";
        return false;
    }
    RecipeActionGrant grant;
    grant.owner = owner;
    grant.recipeRevision = recipeRevision;
    grant.approvedScope = std::move(scope);
    grant.issued = now;
    grant.deadlineUtcMs = now.utcMs + lifetimeMs;
    grant.grantLifetimeSeconds = grantLifetimeSeconds;
    grant.leaseDurationSeconds = leaseDurationSeconds;
    grant.maxActions = maxActions;
    grant.maxCumulativeDurationSeconds = maxCumulativeDurationSeconds;
    recipeGrants_.emplace(owner, std::move(grant));
    error->clear();
    return true;
}

bool RestrictionLeaseController::ApplyRecipeAction(
    const std::string& owner, std::uint64_t recipeRevision,
    const std::string& eventId,
    const std::string& leaseId, const RestrictionPlan& actionPlan,
    RestrictionNow now, RestrictionLease* output, std::string* error) {
    if (error == nullptr || output == nullptr) return false;
    const auto found = recipeGrants_.find(owner);
    if (found == recipeGrants_.end()) {
        *error = "active_grant_missing";
        return false;
    }
    RecipeActionGrant& grant = found->second;
    if (recipeRevision != grant.recipeRevision) {
        *error = "recipe_revision_changed";
        return false;
    }
    if (eventId.empty() || eventId.size() > 128 ||
        eventId.find_first_of("\r\n") != std::string::npos ||
        eventId.find('\0') != std::string::npos) {
        *error = "trigger_event_invalid";
        return false;
    }
    if (grant.consumedEvents.count(eventId) != 0) {
        *error = "trigger_event_replayed";
        return false;
    }
    const std::uint64_t elapsedMono = now.monotonicMs >= grant.issued.monotonicMs
        ? now.monotonicMs - grant.issued.monotonicMs
        : std::numeric_limits<std::uint64_t>::max();
    if (elapsedMono >= static_cast<std::uint64_t>(grant.grantLifetimeSeconds) * 1000ULL ||
        now.utcMs < grant.issued.utcMs || now.utcMs >= grant.deadlineUtcMs) {
        recipeGrants_.erase(found);
        *error = "active_grant_expired";
        return false;
    }
    if (!HeartbeatCurrent(now)) {
        recipeGrants_.erase(found);
        *error = "engine_heartbeat_missing";
        return false;
    }
    const RestrictionPlan& scope = grant.approvedScope;
    const bool protocolAllowed = scope.protocol == RestrictionProtocol::TcpAndUdp ||
        scope.protocol == actionPlan.protocol;
    if (actionPlan.imagePath != scope.imagePath ||
        actionPlan.userSid != scope.userSid ||
        actionPlan.imageFileIdentity != scope.imageFileIdentity ||
        actionPlan.remoteAddress.empty() || actionPlan.remotePort == 0 ||
        (!scope.remoteAddress.empty() &&
            actionPlan.remoteAddress != scope.remoteAddress) ||
        (scope.remotePort != 0 && actionPlan.remotePort != scope.remotePort) ||
        !protocolAllowed ||
        (actionPlan.protocol != RestrictionProtocol::Tcp &&
         actionPlan.protocol != RestrictionProtocol::Udp) ||
        actionPlan.durationSeconds < 60 ||
        actionPlan.durationSeconds > grant.leaseDurationSeconds) {
        *error = "active_action_outside_approved_scope";
        return false;
    }
    for (const auto& pair : active_) {
        if (pair.second.owner == owner) {
            *error = "owner_already_armed";
            return false;
        }
    }
    if (backend_ == nullptr || leaseId.empty() || leaseId.size() > 128 ||
        active_.count(leaseId) != 0 || active_.size() >= 128) {
        *error = "lease_unavailable";
        return false;
    }
    std::string validationError;
    if (!ValidateRestrictionPlan(actionPlan, &validationError)) {
        *error = validationError;
        return false;
    }
    if (grant.actionsUsed >= grant.maxActions ||
        actionPlan.durationSeconds > grant.maxCumulativeDurationSeconds -
            grant.cumulativeDurationSeconds) {
        *error = "active_action_budget_exhausted";
        return false;
    }
    if (now.utcMs > std::numeric_limits<std::uint64_t>::max() -
        static_cast<std::uint64_t>(actionPlan.durationSeconds) * 1000ULL) {
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
    grant.consumedEvents.insert(eventId);
    ++grant.actionsUsed;
    grant.cumulativeDurationSeconds += actionPlan.durationSeconds;
    creationTimes_.push_back(now.monotonicMs);
    RestrictionLease lease;
    lease.id = leaseId;
    lease.owner = owner;
    lease.planHash = RestrictionPlanHash(actionPlan);
    lease.plan = actionPlan;
    lease.started = now;
    lease.deadlineUtcMs = now.utcMs +
        static_cast<std::uint64_t>(actionPlan.durationSeconds) * 1000ULL;
    std::vector<std::uint64_t> ids;
    if (!backend_->Install(actionPlan, &ids, error) || ids.empty() || ids.size() > 4) {
        if (error->empty()) *error = "filter_install_failed";
        ReleaseAll("install_failure_cleanup", now);
        Record(lease, "failed", *error, now);
        return false;
    }
    lease.filterIds = std::move(ids);
    Record(lease, "active", "active_recipe_action_verified", now);
    active_.emplace(leaseId, lease);
    *output = std::move(lease);
    error->clear();
    return true;
}

void RestrictionLeaseController::ReleaseOwner(const std::string& owner,
                                               RestrictionNow now) {
    recipeGrants_.erase(owner);
    for (auto it = approvals_.begin(); it != approvals_.end();) {
        if (it->second.owner == owner) it = approvals_.erase(it);
        else ++it;
    }
    std::vector<std::string> ids;
    for (const auto& pair : active_)
        if (pair.second.owner == owner) ids.push_back(pair.first);
    for (const auto& id : ids) {
        std::string error;
        if (!Release(id, &error, now)) return;
        changes_.back().reason = "owner_disarmed";
    }
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
    for (auto it = recipeGrants_.begin(); it != recipeGrants_.end();) {
        const RecipeActionGrant& grant = it->second;
        const bool expired = now.monotonicMs < grant.issued.monotonicMs ||
            now.monotonicMs - grant.issued.monotonicMs >=
                static_cast<std::uint64_t>(grant.grantLifetimeSeconds) * 1000ULL ||
            now.utcMs < grant.issued.utcMs || now.utcMs >= grant.deadlineUtcMs;
        if (expired) it = recipeGrants_.erase(it);
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
    recipeGrants_.clear();
    if (backend_ != nullptr) backend_->Close();
    for (const auto& pair : active_)
        Record(pair.second, reason == "broker_exit" ? "ended_by_broker_exit" : "released",
               reason, now);
    active_.clear();
    heartbeatSeen_ = false;
}

}  // namespace wintcp
