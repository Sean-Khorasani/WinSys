// Script.h
// SPDX-License-Identifier: Apache-2.0
// The WinTCP Script engine. Extracted from CliCommands.cpp so the CLI
// translation unit stays a front end rather than a language runtime.
#pragma once

#include "Commands.h"   // ScriptOptions, CommandResult

namespace wintcp {
namespace Script {

// Execute `script` according to its options. This is the engine behind
// wintcp::CmdScript (declared in Commands.h), which the CLI dispatcher calls.
CommandResult CmdScript(const ScriptOptions& opt);

}  // namespace Script
}  // namespace wintcp
