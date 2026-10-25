// RecipeModel.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "NetworkEvents.h"

namespace wintcp {

enum class RecipeTrigger { OutboundActivity, NewListener };
enum class RecipeScheduleType { Always, WeeklyWindow };

struct RecipeSchedule {
    RecipeScheduleType type = RecipeScheduleType::Always;
    // Sunday is bit 0 through Saturday at bit 6. For a window crossing
    // midnight, the selected day is the day on which the window starts.
    std::uint8_t daysMask = 0;
    std::uint16_t startMinute = 0;
    std::uint16_t endMinute = 0;
    std::string timeZoneId;
};

// F1's snapshot-capable Passive subset. Unsupported trigger/action/mode values
// are rejected, not silently converted to this weaker source.
struct RecipeDef {
    std::string id;
    std::string name;
    std::string imagePath;
    RecipeTrigger trigger = RecipeTrigger::OutboundActivity;
    RecipeSchedule schedule;
    unsigned cooldownSeconds = 60;
    std::uint64_t revision = 1;
    bool enabled = false;
};

const char* RecipeTriggerName(RecipeTrigger trigger);
bool RecipeScheduleMatchesLocalTime(const RecipeSchedule& schedule,
                                    unsigned weekdaySundayZero,
                                    unsigned minuteOfDay);
bool ValidateRecipe(const RecipeDef& recipe, std::string* error);
std::string FormatRecipes(const std::vector<RecipeDef>& recipes);
std::string RecipesRevision(const std::vector<RecipeDef>& recipes);
bool ParseRecipes(const std::string& text, std::vector<RecipeDef>* recipes,
                  std::string* error);
std::string RecipeJson(const RecipeDef& recipe);
// Applies one typed CLI/API mutation without I/O or side effects. `create`
// carries a one-recipe versioned file; other actions carry a recipe ID.
bool ApplyRecipeChange(const std::vector<RecipeDef>& current,
                       const std::string& action, const std::string& value,
                       std::vector<RecipeDef>* next, std::string* error);
bool ValidateRecipeUpdate(const std::vector<RecipeDef>& current,
                          const std::vector<RecipeDef>& next,
                          std::string* error);
// Returns owners whose revision-bound Active authorization must be discarded
// after a validated recipe transition. The caller also releases broker-owned
// grants/leases and clears any queued action for each returned owner.
std::vector<std::string> RecipeOwnersToInvalidate(
    const std::vector<RecipeDef>& current,
    const std::vector<RecipeDef>& next);
// Gate for privileged automatic actions. `sameUser` must be verified by the
// caller against the current engine identity; ordinary Passive evaluation does
// not require it.
bool RecipeActionEventEligible(const RecipeDef& recipe,
                               const NetworkEvent& event,
                               bool sameUser);

struct RecipeHit {
    bool matched = false;
    bool fire = false;
    std::string reason;
    std::string coverage;
    std::uint64_t suppressed = 0;
    std::string cooldownKey;
    std::uint64_t cooldownUntilMonotonicNs = 0;
};

// Passive notification cooldown does not revoke an independently approved
// Active action. The caller still verifies the user and broker grant.
bool RecipeActionCandidateEligible(const RecipeHit& hit,
                                   const RecipeDef& recipe,
                                   const NetworkEvent& event);

struct RecipeRuntimeStatus {
    std::uint64_t revision = 0;
    std::uint64_t lastTriggeredMonotonicNs = 0;
    std::uint64_t cooldownUntilMonotonicNs = 0;
    std::uint64_t suppressed = 0;
    std::string lastEventId;
    std::string lastOccurredAtUtc;
    std::string lastReason;
};

std::string RecipeNotificationJson(const RecipeDef& recipe,
                                   const NetworkEvent& event,
                                   const RecipeHit& hit,
                                   const std::string& notificationId,
                                   std::uint64_t savedMonotonicNs,
                                   std::uint64_t savedUtcMs);

// One evaluator shared by every UI. It consumes normalized evidence only;
// callers own persistence and delivery of a fired notification.
class RecipeEvaluator {
public:
    RecipeHit Evaluate(const RecipeDef& recipe, const NetworkEvent& event);
    RecipeRuntimeStatus Status(const std::string& recipeId,
                               std::uint64_t revision) const;
    void Clear(const std::string& recipeId);
    void Reconcile(const std::vector<RecipeDef>& recipes);
    std::size_t RememberedKeys() const { return nextFireNs_.size(); }
    std::string Checkpoint(std::uint64_t nowNs, std::uint64_t utcMs) const;
    bool Restore(const std::string& text, std::uint64_t nowNs,
                 std::uint64_t utcMs, std::string* error);
    bool RecoverFiredCooldown(const std::string& key,
                              std::uint64_t remainingNs,
                              std::uint64_t savedMonotonicNs,
                              std::uint64_t savedUtcMs,
                              std::uint64_t nowNs,
                              std::uint64_t nowUtcMs);

private:
    struct CrossSourceObservation {
        std::uint64_t snapshotNs = 0;
        std::uint64_t etwNs = 0;
    };
    std::map<std::string, std::uint64_t> nextFireNs_;
    std::map<std::string, std::uint64_t> suppressed_;
    std::map<std::string, RecipeRuntimeStatus> runtime_;
    std::map<std::string, CrossSourceObservation> crossSourceObservations_;
};

}  // namespace wintcp
