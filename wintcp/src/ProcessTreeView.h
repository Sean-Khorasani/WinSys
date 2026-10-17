// ProcessTreeView.h
// SPDX-License-Identifier: Apache-2.0
// The ONE implementation of "rows -> tree items" for the process-tree view.
//
// The engine half (ProcessTree: BuildProcessTree over the rows the store
// already holds) and the killtree verb are pure and shipped; this is the
// view-side translation - aggregate the rows to one node per process and
// insert them under their parents. It is a free function over a HWND rather
// than a window class because the view is a MODE of the main window (a tree
// control where the list view is, like Task Manager's Processes tab), not a
// window of its own: two surfaces showing one hierarchy are two answers to
// the same question, and answers drift.
//
// The rules come from the engine, not from here: a node whose parent is not
// in the set is a root ("nobody claims me", not "PPID is 0"), a cycle is
// broken rather than followed, and an over-deep chain is reported.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>

#include <string>
#include <vector>

namespace wintcp {

// One process, already deduplicated. 'connections' is decoration for the
// label ("name  (PID n, k connections)") and never affects the SHAPE: the
// caller counts them from the connection table and passes the number in,
// so this module holds no socket knowledge and a tree of all processes with
// no connections at all renders exactly the same shape.
struct ProcessTreeNode {
    DWORD pid = 0;
    DWORD ppid = 0;
    bool ppidKnown = true;
    std::wstring name;
    size_t connections = 0;
};

// Empties 'tree' and refills it: one item per PROCESS in 'procs'
// (exactly what is passed, so the caller decides which processes exist),
// placed under its parent where the parent is also in the set and as a root
// otherwise. Roots are expanded one level, so the forest reads as a tree on
// open, and the first root is selected so the arrow keys work immediately.
//
// Returns the process count. '*depthExceeded' receives the engine's ceiling
// flag so the caller can say so rather than truncating silently.
//
// 'procs' is copied by the caller before the first insert, so a refresh that
// replaces the store (or re-enumerates the machine) mid-render cannot
// corrupt the tree.
size_t ProcessTreeFill(HWND tree, const std::vector<ProcessTreeNode>& procs,
                       bool* depthExceeded);

}  // namespace wintcp
