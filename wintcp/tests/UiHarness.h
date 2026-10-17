// UiHarness.h
//
// In-process behavioural verification of the main window.
//
// Kept out of Bench.cpp deliberately: this needs a live HWND and a message
// pump, whereas the selftest is a pure-logic runner with no window. Splitting
// them means a headless selftest run stays headless.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <string>

namespace wintcp {

class MainWindow;

// Drives the window through its real WndProc and reports what changed.
// Returns a short verdict suitable for printing alongside the other results.
std::wstring RunUiHarness(MainWindow& window, HWND hwnd);

}  // namespace wintcp
