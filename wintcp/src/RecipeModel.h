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

// F1's snapshot-capable Passive subset. Unsupported trigger/action/mode values
// are rejected, not silently converted to this weaker source.
struct RecipeDef {
    std::string id;
    std::string name;
    std::string imagePath;
    RecipeTrigger trigger = RecipeTrigger::OutboundActivity;
    unsigned cooldownSeconds = 60;
    std::uint64_t revision = 1;
    bool enabled = false;
};

const char* RecipeTriggerName(RecipeTrigger trigger);
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

struct RecipeHit {
    bool matched = false;
    bool fire = false;
    std::string reason;
    std::string coverage;
    std::uint64_t suppressed = 0;
};

std::string RecipeNotificationJson(const RecipeDef& recipe,
                                   const NetworkEvent& event,
                                   const RecipeHit& hit,
                                   const std::string& notificationId);

// One evaluator shared by every UI. It consumes normalized evidence only;
// callers own persistence and delivery of a fired notification.
class RecipeEvaluator {
public:
    RecipeHit Evaluate(const RecipeDef& recipe, const NetworkEvent& event);
    void Clear(const std::string& recipeId);
    void Reconcile(const std::vector<RecipeDef>& recipes);
    std::size_t RememberedKeys() const { return nextFireNs_.size(); }
    std::string Checkpoint(std::uint64_t nowNs, std::uint64_t utcMs) const;
    bool Restore(const std::string& text, std::uint64_t nowNs,
                 std::uint64_t utcMs, std::string* error);

private:
    std::map<std::string, std::uint64_t> nextFireNs_;
    std::map<std::string, std::uint64_t> suppressed_;
};

}  // namespace wintcp
