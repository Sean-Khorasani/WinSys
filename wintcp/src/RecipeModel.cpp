// RecipeModel.cpp
// SPDX-License-Identifier: Apache-2.0
#include "RecipeModel.h"
#include "Sha256.h"

#include <algorithm>
#include <limits>
#include <set>
#include <sstream>

namespace wintcp {
namespace {
constexpr std::size_t kMaxRecipes = 100;
constexpr std::size_t kMaxConfigBytes = 256 * 1024;
constexpr std::uint64_t kCrossSourceWindowNs = 120000000000ULL;

std::string Hex(const std::string& text) {
    static const char kDigits[] = "0123456789abcdef";
    std::string result;
    result.reserve(text.size() * 2);
    for (unsigned char c : text) {
        result += kDigits[c >> 4];
        result += kDigits[c & 15];
    }
    return result;
}

bool Unhex(const std::string& text, std::string* result) {
    if ((text.size() & 1) != 0) return false;
    result->clear();
    for (std::size_t i = 0; i < text.size(); i += 2) {
        const auto digit = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            return -1;
        };
        const int high = digit(text[i]), low = digit(text[i + 1]);
        if (high < 0 || low < 0) return false;
        result->push_back(static_cast<char>((high << 4) | low));
    }
    return true;
}

bool Decimal(const std::string& text, std::uint64_t* result) {
    if (text.empty()) return false;
    std::uint64_t value = 0;
    for (char c : text) {
        if (c < '0' || c > '9') return false;
        const unsigned digit = static_cast<unsigned>(c - '0');
        if (value > ((std::numeric_limits<std::uint64_t>::max)() - digit) / 10)
            return false;
        value = value * 10 + digit;
    }
    *result = value;
    return true;
}

bool Printable(const std::string& text) {
    if (text.empty()) return false;
    for (unsigned char c : text)
        if (c == 0 || c < 0x20 || c == 0x7f) return false;
    return true;
}

char LowerAscii(char c) {
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
}

bool SamePath(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (LowerAscii(a[i]) != LowerAscii(b[i])) return false;
    return true;
}

bool Loopback(const std::string& address) {
    std::string lower;
    lower.reserve(address.size());
    for (char c : address) lower += LowerAscii(c);
    return lower.rfind("127.", 0) == 0 || lower == "::1" ||
           lower.rfind("::ffff:127.", 0) == 0;
}

std::string Quote(const std::string& value) {
    static const char kHex[] = "0123456789abcdef";
    std::string out = "\"";
    for (unsigned char c : value) {
        if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
        else if (c < 0x20) {
            out += "\\u00";
            out += kHex[c >> 4];
            out += kHex[c & 15];
        } else out += static_cast<char>(c);
    }
    return out + '"';
}
}  // namespace

const char* RecipeTriggerName(RecipeTrigger trigger) {
    switch (trigger) {
    case RecipeTrigger::OutboundActivity: return "outbound_activity";
    case RecipeTrigger::NewListener: return "new_listener";
    }
    return "unsupported";
}

bool RecipeActionEventEligible(const RecipeDef& recipe,
                               const NetworkEvent& event,
                               bool sameUser) {
    if (!sameUser || !recipe.enabled ||
        recipe.trigger != RecipeTrigger::OutboundActivity ||
        event.eventId.empty() || event.incompleteChronology || event.lateArrival ||
        event.direction != "outbound" || !event.remote.known ||
        event.endpointRoleConfidence != "source_semantics" ||
        event.remote.address.empty() || event.remote.port == 0 ||
        Loopback(event.remote.address) || !ProcessActionable(event.process) ||
        !SamePath(recipe.imagePath, event.process.imagePath)) return false;
    return (event.kind == NetworkEventKind::ConnectionEstablished &&
            event.transport == "tcp") ||
        (event.kind == NetworkEventKind::UdpActivity && event.transport == "udp");
}

bool RecipeActionCandidateEligible(const RecipeHit& hit,
                                  const RecipeDef& recipe,
                                  const NetworkEvent& event) {
    return hit.matched && RecipeActionEventEligible(recipe, event, true);
}

bool ValidateRecipe(const RecipeDef& recipe, std::string* error) {
    const auto fail = [error](const char* reason) {
        if (error != nullptr) *error = reason;
        return false;
    };
    if (recipe.id.empty() || recipe.id.size() > 64) return fail("invalid_id");
    for (char c : recipe.id)
        if ((c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-')
            return fail("invalid_id");
    if (recipe.name.size() > 120 || !Printable(recipe.name))
        return fail("invalid_name");
    if (recipe.imagePath.size() > 1024 || !Printable(recipe.imagePath) ||
        !(recipe.imagePath.size() >= 3 &&
          ((recipe.imagePath[1] == ':' && recipe.imagePath[2] == '\\') ||
           (recipe.imagePath[0] == '\\' && recipe.imagePath[1] == '\\'))))
        return fail("invalid_image_path");
    if (recipe.cooldownSeconds > 86400 || recipe.revision == 0)
        return fail("invalid_limit");
    if (std::string(RecipeTriggerName(recipe.trigger)) == "unsupported")
        return fail("unsupported_trigger");
    if (error != nullptr) error->clear();
    return true;
}

std::string FormatRecipes(const std::vector<RecipeDef>& recipes) {
    std::string out = "WinTCP-Recipes:1\n";
    for (const RecipeDef& recipe : recipes)
        out += recipe.id + '|' + std::to_string(recipe.revision) + '|' +
            (recipe.enabled ? "1" : "0") + '|' +
            RecipeTriggerName(recipe.trigger) + '|' +
            std::to_string(recipe.cooldownSeconds) + '|' +
            Hex(recipe.name) + '|' + Hex(recipe.imagePath) + '\n';
    return out;
}

std::string RecipesRevision(const std::vector<RecipeDef>& recipes) {
    const std::string canonical = FormatRecipes(recipes);
    return Sha256HexA(Sha256Bytes(
        reinterpret_cast<const unsigned char*>(canonical.data()),
        canonical.size()));
}

bool ParseRecipes(const std::string& text, std::vector<RecipeDef>* recipes,
                  std::string* error) {
    if (recipes == nullptr || text.size() > kMaxConfigBytes ||
        text.rfind("WinTCP-Recipes:1\n", 0) != 0) {
        if (error != nullptr) *error = "invalid_recipe_header";
        return false;
    }
    std::vector<RecipeDef> parsed;
    std::set<std::string> ids;
    std::size_t at = 17;  // bytes in "WinTCP-Recipes:1\n"
    while (at < text.size()) {
        const std::size_t end = text.find('\n', at);
        if (end == std::string::npos || end - at > 4096 || parsed.size() >= kMaxRecipes) {
            if (error != nullptr) *error = "invalid_recipe_line";
            return false;
        }
        const std::string line = text.substr(at, end - at);
        std::vector<std::string> fields;
        std::size_t start = 0;
        for (;;) {
            const std::size_t split = line.find('|', start);
            fields.push_back(line.substr(start, split == std::string::npos
                ? std::string::npos : split - start));
            if (split == std::string::npos) break;
            start = split + 1;
        }
        std::uint64_t revision = 0, cooldown = 0;
        RecipeDef recipe;
        if (fields.size() != 7 || !Decimal(fields[1], &revision) ||
            !Decimal(fields[4], &cooldown) || cooldown > 86400 ||
            (fields[2] != "0" && fields[2] != "1") ||
            !Unhex(fields[5], &recipe.name) ||
            !Unhex(fields[6], &recipe.imagePath)) {
            if (error != nullptr) *error = "invalid_recipe_field";
            return false;
        }
        recipe.id = fields[0];
        recipe.revision = revision;
        recipe.cooldownSeconds = static_cast<unsigned>(cooldown);
        recipe.enabled = fields[2] == "1";
        if (fields[3] == "outbound_activity")
            recipe.trigger = RecipeTrigger::OutboundActivity;
        else if (fields[3] == "new_listener")
            recipe.trigger = RecipeTrigger::NewListener;
        else {
            if (error != nullptr) *error = "unsupported_trigger";
            return false;
        }
        if (!ValidateRecipe(recipe, error) || !ids.insert(recipe.id).second) {
            if (error != nullptr && error->empty()) *error = "duplicate_recipe";
            return false;
        }
        parsed.push_back(std::move(recipe));
        at = end + 1;
    }
    *recipes = std::move(parsed);
    if (error != nullptr) error->clear();
    return true;
}

std::string RecipeJson(const RecipeDef& recipe) {
    return "{\"schemaVersion\":1,\"id\":" + Quote(recipe.id) +
        ",\"revision\":\"" + std::to_string(recipe.revision) +
        "\",\"name\":" + Quote(recipe.name) +
        ",\"enabled\":" + (recipe.enabled ? "true" : "false") +
        ",\"mode\":\"passive\",\"target\":{\"imagePaths\":[" +
        Quote(recipe.imagePath) + "],\"includeChildren\":false}," +
        "\"trigger\":{\"type\":" + Quote(RecipeTriggerName(recipe.trigger)) +
        "},\"schedule\":{\"type\":\"always\"},\"actions\":[{\"type\":\"notify\"}]," +
        "\"cooldownSeconds\":" + std::to_string(recipe.cooldownSeconds) + "}";
}

bool ApplyRecipeChange(const std::vector<RecipeDef>& current,
                       const std::string& action, const std::string& value,
                       std::vector<RecipeDef>* next, std::string* error) {
    if (next == nullptr || error == nullptr) return false;
    *next = current;
    error->clear();
    if (action == "create") {
        std::vector<RecipeDef> candidate;
        if (!ParseRecipes(value, &candidate, error) || candidate.size() != 1 ||
            candidate[0].enabled || candidate[0].revision != 1) {
            *error = "bad_recipe";
            return false;
        }
        if (next->size() >= kMaxRecipes) {
            *error = "recipe_capacity_exceeded";
            return false;
        }
        const auto found = std::find_if(next->begin(), next->end(),
            [&candidate](const RecipeDef& row) { return row.id == candidate[0].id; });
        if (found != next->end()) { *error = "recipe_exists"; return false; }
        next->push_back(std::move(candidate[0]));
        return true;
    }
    if (action != "enable" && action != "disable" && action != "remove") {
        *error = "unsupported_action";
        return false;
    }
    if (value.empty() || value.size() > 64 ||
        value.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-") !=
            std::string::npos) {
        *error = "invalid_id";
        return false;
    }
    const auto found = std::find_if(next->begin(), next->end(),
        [&value](const RecipeDef& row) { return row.id == value; });
    if (found == next->end()) { *error = "recipe_not_found"; return false; }
    if (action == "remove") {
        next->erase(found);
    } else if (found->enabled != (action == "enable")) {
        if (found->revision == (std::numeric_limits<std::uint64_t>::max)()) {
            *error = "revision_exhausted";
            return false;
        }
        found->enabled = action == "enable";
        ++found->revision;
    }
    return true;
}

bool ValidateRecipeUpdate(const std::vector<RecipeDef>& current,
                          const std::vector<RecipeDef>& next,
                          std::string* error) {
    if (error == nullptr) return false;
    error->clear();
    if (next.size() > kMaxRecipes) {
        *error = "recipe_capacity_exceeded";
        return false;
    }
    std::set<std::string> ids;
    for (const RecipeDef& after : next) {
        if (!ValidateRecipe(after, error)) return false;
        if (!ids.insert(after.id).second) {
            *error = "duplicate_recipe";
            return false;
        }
        const auto before = std::find_if(current.begin(), current.end(),
            [&after](const RecipeDef& row) { return row.id == after.id; });
        if (before == current.end()) {
            if (after.revision != 1 || after.enabled) {
                *error = "new_recipe_must_start_disabled";
                return false;
            }
            continue;
        }
        const bool sensitive = before->imagePath != after.imagePath ||
            before->trigger != after.trigger ||
            before->cooldownSeconds != after.cooldownSeconds;
        const bool changed = sensitive || before->name != after.name ||
            before->enabled != after.enabled;
        if (changed) {
            if (before->revision == (std::numeric_limits<std::uint64_t>::max)() ||
                after.revision != before->revision + 1) {
                *error = "recipe_revision_conflict";
                return false;
            }
            if (sensitive && after.enabled) {
                *error = "changed_recipe_requires_review";
                return false;
            }
        } else if (after.revision != before->revision) {
            *error = "recipe_revision_conflict";
            return false;
        }
    }
    return true;
}

std::vector<std::string> RecipeOwnersToInvalidate(
    const std::vector<RecipeDef>& current,
    const std::vector<RecipeDef>& next) {
    std::vector<std::string> owners;
    for (const RecipeDef& before : current) {
        if (!before.enabled) continue;
        const auto after = std::find_if(next.begin(), next.end(),
            [&before](const RecipeDef& recipe) { return recipe.id == before.id; });
        if (after == next.end() || !after->enabled ||
            after->revision != before.revision)
            owners.push_back("recipe:" + before.id);
    }
    return owners;
}

std::string RecipeNotificationJson(const RecipeDef& recipe,
                                   const NetworkEvent& event,
                                   const RecipeHit& hit,
                                   const std::string& notificationId,
                                   std::uint64_t savedMonotonicNs,
                                   std::uint64_t savedUtcMs) {
    const bool listener = recipe.trigger == RecipeTrigger::NewListener;
    const NetworkEndpoint& endpoint = listener ? event.local : event.remote;
    const std::string target = endpoint.address + ':' +
        std::to_string(endpoint.port);
    const std::string message = listener
        ? "New TCP listener for " + recipe.name + " at " + target +
          ". Binding observed; external reachability is not established."
        : event.kind == NetworkEventKind::ConnectionEstablished
            ? "Outbound TCP connection established by " + recipe.name + " to " + target + "."
            : event.kind == NetworkEventKind::UdpActivity
                ? "Outbound UDP activity observed for " + recipe.name + " to " + target + "."
                : "New TCP remote endpoint for " + recipe.name + " at " + target +
                  ". Snapshot sighting; direction and connection attempt are not established.";
    return "{\"schemaVersion\":1,\"id\":" + Quote(notificationId) +
        ",\"recipeId\":" + Quote(recipe.id) +
        ",\"recipeRevision\":\"" + std::to_string(recipe.revision) +
        "\",\"eventId\":" + Quote(event.eventId) +
        ",\"occurredAtUtc\":" + Quote(event.occurredAtUtc) +
        ",\"monotonicNs\":\"" + std::to_string(event.monotonicNs) +
        "\",\"reason\":" + Quote(hit.reason) +
        ",\"coverage\":" + Quote(hit.coverage) +
        ",\"message\":" + Quote(message) +
        ",\"acknowledged\":false,\"deliveryStatus\":\"inbox\"," +
        "\"suppressed\":\"" + std::to_string(hit.suppressed) +
        "\",\"recoveryCooldownKey\":" + Quote(hit.cooldownKey) +
        ",\"recoveryCooldownRemainingNs\":\"" + std::to_string(
            hit.cooldownUntilMonotonicNs > savedMonotonicNs
                ? hit.cooldownUntilMonotonicNs - savedMonotonicNs : 0) +
        "\",\"recoverySavedMonotonicNs\":\"" +
        std::to_string(savedMonotonicNs) +
        "\",\"recoverySavedUtcMs\":\"" + std::to_string(savedUtcMs) + "\"}";
}

RecipeHit RecipeEvaluator::Evaluate(const RecipeDef& recipe,
                                     const NetworkEvent& event) {
    RecipeHit hit;
    const bool snapshot = event.kind == NetworkEventKind::EndpointObserved;
    if (!recipe.enabled || event.process.imagePath.empty() ||
        !SamePath(recipe.imagePath, event.process.imagePath)) return hit;
    if (recipe.trigger == RecipeTrigger::OutboundActivity) {
        if (snapshot) {
            if (event.firstObservedMidSession || event.transport != "tcp" ||
                event.tcpState != "established" || !event.remote.known ||
                Loopback(event.remote.address)) return hit;
            hit.reason = "new_remote_tcp_endpoint";
            hit.coverage = "snapshot_tcp_appearance_direction_unknown";
        } else if (event.kind == NetworkEventKind::ConnectionEstablished &&
                   event.transport == "tcp" && event.direction == "outbound" &&
                   event.remote.known && !Loopback(event.remote.address)) {
            hit.reason = "outbound_tcp_connection_established";
            hit.coverage = "etw_tcp_lifecycle_normalized";
        } else if (event.kind == NetworkEventKind::UdpActivity &&
                   event.transport == "udp" && event.direction == "outbound" &&
                   event.remote.known && !Loopback(event.remote.address)) {
            hit.reason = "outbound_udp_activity";
            hit.coverage = "etw_udp_send_normalized";
        } else return hit;
    } else if (recipe.trigger == RecipeTrigger::NewListener) {
        if (!snapshot || event.firstObservedMidSession || event.transport != "tcp" ||
            event.tcpState != "listen" || !event.local.known ||
            Loopback(event.local.address)) return hit;
        hit.reason = "new_tcp_listener";
        hit.coverage = "snapshot_listener_binding";
    } else return hit;
    hit.matched = true;
    std::string key = recipe.id + ':' + std::to_string(recipe.revision) + ':' +
        std::to_string(event.process.pid) + ':' +
        (event.process.creationTimeKnown
            ? std::to_string(event.process.creationTimeFileTime) : "unverified");
    if (recipe.trigger == RecipeTrigger::NewListener)
        key += ':' + event.local.address + ':' + std::to_string(event.local.port);
    hit.cooldownKey = key;
    // A snapshot and the normalized ETW establish event can describe the same
    // outbound TCP flow. Correlate only complete tuples and verified process
    // identity; journal evidence remains untouched, and Active eligibility is
    // evaluated independently by the caller.
    const bool snapshotFlow = snapshot && event.transport == "tcp" &&
        event.local.known && event.remote.known && event.local.port != 0 &&
        event.remote.port != 0;
    const bool etwFlow = event.kind == NetworkEventKind::ConnectionEstablished &&
        event.source == "etw_tcp" && event.transport == "tcp" &&
        event.direction == "outbound" && event.local.known && event.remote.known &&
        event.local.port != 0 && event.remote.port != 0;
    if (recipe.trigger == RecipeTrigger::OutboundActivity &&
        (snapshotFlow || etwFlow) && event.process.creationTimeKnown) {
        const auto endpointPart = [](const NetworkEndpoint& endpoint) {
            std::string address = endpoint.address;
            for (char& c : address) c = LowerAscii(c);
            return std::to_string(address.size()) + ':' + address + ':' +
                std::to_string(endpoint.port) + ':' +
                std::to_string(endpoint.scopeId);
        };
        const std::string flowKey = recipe.id + ':' +
            std::to_string(recipe.revision) + ':' +
            std::to_string(event.process.pid) + ':' +
            std::to_string(event.process.creationTimeFileTime) + ':' +
            endpointPart(event.local) + ':' + endpointPart(event.remote);
        if (crossSourceObservations_.find(flowKey) == crossSourceObservations_.end() &&
            crossSourceObservations_.size() >= 10000) {
            auto oldest = crossSourceObservations_.begin();
            for (auto it = crossSourceObservations_.begin();
                 it != crossSourceObservations_.end(); ++it) {
                const auto age = (std::max)(it->second.snapshotNs, it->second.etwNs);
                const auto oldestAge = (std::max)(oldest->second.snapshotNs,
                                                   oldest->second.etwNs);
                if (age < oldestAge) oldest = it;
            }
            crossSourceObservations_.erase(oldest);
        }
        auto& observed = crossSourceObservations_[flowKey];
        std::uint64_t& sameSourceNs = snapshotFlow
            ? observed.snapshotNs : observed.etwNs;
        const std::uint64_t otherSourceNs = snapshotFlow
            ? observed.etwNs : observed.snapshotNs;
        const bool crossSourceDuplicate = otherSourceNs != 0 &&
            (event.monotonicNs >= otherSourceNs
                ? event.monotonicNs - otherSourceNs
                : otherSourceNs - event.monotonicNs) <= kCrossSourceWindowNs;
        sameSourceNs = event.monotonicNs;
        if (crossSourceDuplicate) {
            if (suppressed_[key] != (std::numeric_limits<std::uint64_t>::max)())
                ++suppressed_[key];
            hit.suppressed = suppressed_[key];
            auto& status = runtime_[recipe.id];
            status.revision = recipe.revision;
            return hit;
        }
    }
    auto last = nextFireNs_.find(key);
    const std::uint64_t cooldownNs =
        static_cast<std::uint64_t>(recipe.cooldownSeconds) * 1000000000ULL;
    if (last != nextFireNs_.end() && event.monotonicNs < last->second) {
        if (suppressed_[key] != (std::numeric_limits<std::uint64_t>::max)())
            ++suppressed_[key];
        hit.suppressed = suppressed_[key];
        auto& status = runtime_[recipe.id];
        status.revision = recipe.revision;
        return hit;
    }
    if (last == nextFireNs_.end() && nextFireNs_.size() >= 10000) {
        const auto oldest = std::min_element(nextFireNs_.begin(), nextFireNs_.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });
        if (oldest != nextFireNs_.end()) {
            suppressed_.erase(oldest->first);
            nextFireNs_.erase(oldest);
        }
    }
    nextFireNs_[key] = event.monotonicNs >
        (std::numeric_limits<std::uint64_t>::max)() - cooldownNs
        ? (std::numeric_limits<std::uint64_t>::max)() : event.monotonicNs + cooldownNs;
    hit.cooldownUntilMonotonicNs = nextFireNs_[key];
    hit.fire = true;
    hit.suppressed = suppressed_[key];
    suppressed_[key] = 0;
    auto& status = runtime_[recipe.id];
    status.revision = recipe.revision;
    status.lastTriggeredMonotonicNs = event.monotonicNs;
    status.lastEventId = event.eventId;
    status.lastOccurredAtUtc = event.occurredAtUtc;
    status.lastReason = hit.reason;
    return hit;
}

RecipeRuntimeStatus RecipeEvaluator::Status(const std::string& recipeId,
                                           std::uint64_t revision) const {
    const auto found = runtime_.find(recipeId);
    RecipeRuntimeStatus status = found == runtime_.end() ||
        found->second.revision != revision ? RecipeRuntimeStatus{} : found->second;
    status.revision = revision;
    const std::string prefix = recipeId + ':' + std::to_string(revision) + ':';
    for (const auto& entry : nextFireNs_) {
        if (entry.first.rfind(prefix, 0) != 0) continue;
        status.cooldownUntilMonotonicNs = (std::max)(status.cooldownUntilMonotonicNs,
                                                      entry.second);
        const auto count = suppressed_.find(entry.first);
        if (count != suppressed_.end()) {
            status.suppressed = count->second >
                (std::numeric_limits<std::uint64_t>::max)() - status.suppressed
                ? (std::numeric_limits<std::uint64_t>::max)()
                : status.suppressed + count->second;
        }
    }
    return status;
}

std::string RecipeEvaluator::Checkpoint(std::uint64_t nowNs, std::uint64_t utcMs) const {
    std::string text = "WinTCP-Recipe-Cooldowns:1\n" + std::to_string(nowNs) +
        ' ' + std::to_string(utcMs) + '\n';
    for (const auto& entry : nextFireNs_) {
        if (entry.second <= nowNs) continue;
        const auto count = suppressed_.find(entry.first);
        text += Hex(entry.first) + ' ' + std::to_string(entry.second - nowNs) +
            ' ' + std::to_string(count == suppressed_.end() ? 0 : count->second) + '\n';
    }
    return text;
}

bool RecipeEvaluator::Restore(const std::string& text, std::uint64_t nowNs,
                               std::uint64_t utcMs, std::string* error) {
    if (error == nullptr) return false;
    *error = "cooldown_checkpoint_invalid";
    if (text.size() > 4 * 1024 * 1024 || text.empty() || text.back() != '\n') return false;
    std::istringstream input(text);
    std::string line, first, second, third, extra;
    if (!std::getline(input, line) || line != "WinTCP-Recipe-Cooldowns:1" ||
        !std::getline(input, line)) return false;
    std::istringstream anchor(line);
    std::uint64_t savedNs = 0, savedUtc = 0;
    if (!(anchor >> first >> second) || (anchor >> extra) ||
        !Decimal(first, &savedNs) || !Decimal(second, &savedUtc)) return false;
    // Only charge offline time when both clocks corroborate it. Reboot, wall
    // jumps, and uncertain mappings conservatively retain remaining cooldown.
    std::uint64_t elapsed = 0;
    if (nowNs >= savedNs && utcMs >= savedUtc) {
        const auto mono = nowNs - savedNs;
        const auto wall = utcMs - savedUtc;
        const auto monoMs = mono / 1000000ULL;
        const auto difference = monoMs > wall ? monoMs - wall : wall - monoMs;
        if (difference <= 2000) elapsed = mono;
    }
    std::map<std::string, std::uint64_t> deadlines, suppressed;
    std::set<std::string> seen;
    while (std::getline(input, line)) {
        std::istringstream row(line);
        std::string key;
        std::uint64_t remaining = 0, count = 0;
        if (!(row >> first >> second >> third) || (row >> extra) ||
            first.size() > 1024 || !Unhex(first, &key) || !Printable(key) ||
            key.find(':') == std::string::npos || !Decimal(second, &remaining) ||
            remaining > 86400000000000ULL || !Decimal(third, &count) ||
            !seen.insert(key).second || seen.size() > 10000) return false;
        if (remaining <= elapsed) continue;
        remaining -= elapsed;
        if (nowNs > (std::numeric_limits<std::uint64_t>::max)() - remaining) return false;
        deadlines[key] = nowNs + remaining;
        suppressed[key] = count;
    }
    nextFireNs_ = std::move(deadlines);
    suppressed_ = std::move(suppressed);
    error->clear();
    return true;
}

bool RecipeEvaluator::RecoverFiredCooldown(const std::string& key,
                                           std::uint64_t remainingNs,
                                           std::uint64_t savedMonotonicNs,
                                           std::uint64_t savedUtcMs,
                                           std::uint64_t nowNs,
                                           std::uint64_t nowUtcMs) {
    if (key.empty() || key.size() > 1024 || !Printable(key) ||
        remainingNs > 86400000000000ULL || savedUtcMs == 0) return false;
    if (remainingNs == 0) return true;
    std::uint64_t elapsedNs = 0;
    if (nowNs >= savedMonotonicNs && nowUtcMs >= savedUtcMs) {
        const std::uint64_t monotonicDeltaNs = nowNs - savedMonotonicNs;
        const std::uint64_t monotonicDeltaMs = monotonicDeltaNs / 1000000ULL;
        const std::uint64_t wallDeltaMs = nowUtcMs - savedUtcMs;
        const std::uint64_t difference = monotonicDeltaMs > wallDeltaMs
            ? monotonicDeltaMs - wallDeltaMs : wallDeltaMs - monotonicDeltaMs;
        // As with the main checkpoint, only charge offline time when the two
        // clocks corroborate one another. Clock rollback/reboot fails closed
        // by retaining the saved remaining cooldown.
        if (difference <= 2000) elapsedNs = monotonicDeltaNs;
    }
    if (remainingNs <= elapsedNs) return true;
    remainingNs -= elapsedNs;
    if (nowNs > (std::numeric_limits<std::uint64_t>::max)() - remainingNs)
        return false;
    const std::uint64_t recoveredDeadline = nowNs + remainingNs;
    const auto existing = nextFireNs_.find(key);
    if (existing == nextFireNs_.end() || recoveredDeadline > existing->second) {
        if (existing == nextFireNs_.end() && nextFireNs_.size() >= 10000) {
            const auto oldest = std::min_element(nextFireNs_.begin(), nextFireNs_.end(),
                [](const auto& a, const auto& b) { return a.second < b.second; });
            if (oldest != nextFireNs_.end()) {
                suppressed_.erase(oldest->first);
                nextFireNs_.erase(oldest);
            }
        }
        nextFireNs_[key] = recoveredDeadline;
        suppressed_[key] = 0;
    }
    return true;
}

void RecipeEvaluator::Reconcile(const std::vector<RecipeDef>& recipes) {
    std::set<std::string> activePrefixes;
    std::map<std::string, std::uint64_t> revisions;
    for (const auto& recipe : recipes) {
        activePrefixes.insert(recipe.id + ':' + std::to_string(recipe.revision) + ':');
        revisions[recipe.id] = recipe.revision;
    }
    for (auto it = nextFireNs_.begin(); it != nextFireNs_.end();) {
        const auto first = it->first.find(':');
        const auto second = first == std::string::npos ? first : it->first.find(':', first + 1);
        if (second == std::string::npos ||
            activePrefixes.find(it->first.substr(0, second + 1)) == activePrefixes.end()) {
            suppressed_.erase(it->first);
            it = nextFireNs_.erase(it);
        } else ++it;
    }
    for (auto it = runtime_.begin(); it != runtime_.end();) {
        const auto found = revisions.find(it->first);
        if (found == revisions.end() || found->second != it->second.revision)
            it = runtime_.erase(it);
        else ++it;
    }
    for (auto it = crossSourceObservations_.begin();
         it != crossSourceObservations_.end();) {
        const auto first = it->first.find(':');
        const auto second = first == std::string::npos ? first :
            it->first.find(':', first + 1);
        if (second == std::string::npos || activePrefixes.find(
            it->first.substr(0, second + 1)) == activePrefixes.end())
            it = crossSourceObservations_.erase(it);
        else ++it;
    }
}

void RecipeEvaluator::Clear(const std::string& recipeId) {
    const std::string prefix = recipeId + ':';
    for (auto it = nextFireNs_.begin(); it != nextFireNs_.end();) {
        if (it->first.rfind(prefix, 0) == 0) it = nextFireNs_.erase(it);
        else ++it;
    }
    for (auto it = suppressed_.begin(); it != suppressed_.end();) {
        if (it->first.rfind(prefix, 0) == 0) it = suppressed_.erase(it);
        else ++it;
    }
    runtime_.erase(recipeId);
    for (auto it = crossSourceObservations_.begin();
         it != crossSourceObservations_.end();) {
        if (it->first.rfind(recipeId + ':', 0) == 0)
            it = crossSourceObservations_.erase(it);
        else ++it;
    }
}

}  // namespace wintcp
