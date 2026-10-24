// EngineRuntime.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>
#include <vector>
#include "EngineConfig.h"
#include "RecipeModel.h"

namespace wintcp {

// Explicit foreground/background per-user process controls. The ordinary CLI
// never requires this process for endpoint inspection.
int RunEngineCommand(int argc, wchar_t** argv);
bool EngineRequestStatus(std::string* response);
bool EngineRequestEvents(const std::string& cursor, unsigned limit,
                         std::string* response);
bool EngineRequestHistory(const std::string& cursor, unsigned limit,
                          std::string* response);
bool EngineRequestRestrictionHistory(const std::string& cursor, unsigned limit,
                                     std::string* response);
bool EngineRequestLifecycleHistory(const std::string& cursor, unsigned limit,
                                   std::string* response);
bool EngineRequestConfig(std::string* response);
bool EngineSubmitConfig(const std::string& requestId,
                        const std::string& expectedRevision,
                        const EngineConfig& config, std::string* response);
bool EngineRequestOperation(const std::string& operationId,
                            std::string* response);
bool EngineSubmitCollector(const std::string& requestId,
                           const std::string& action,
                           const std::string& payload,
                           std::string* response);
bool EngineRequestRecipes(std::string* response);
bool EngineSubmitRecipes(const std::string& requestId,
                         const std::string& expectedRevision,
                         const std::vector<RecipeDef>& recipes,
                         std::string* response);
bool EngineRecipeMutation(const std::string& requestId,
                          const std::string& expectedRevision,
                          const std::string& action,
                          const std::string& value,
                          std::string* response);
bool EngineTestRecipe(const std::string& recipeId, std::string* response);
bool EngineShowRecipe(const std::string& recipeId, std::string* response);
int RunRecipeCommand(int argc, wchar_t** argv);
bool EngineRequestNotifications(const std::string& cursor, unsigned limit,
                                std::string* response);
bool EngineAcknowledgeNotification(const std::string& requestId,
                                   const std::string& notificationId,
                                   std::string* response);
// Explicit controls for local UIs. Never elevate or register startup work.
bool EngineStart(std::string* error);
bool EngineStop(std::string* error);
bool RuntimeCliPath(std::wstring* path, std::string* error);

}  // namespace wintcp
