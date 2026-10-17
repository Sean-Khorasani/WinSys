// ProcessTreeView.cpp
// SPDX-License-Identifier: Apache-2.0
// See ProcessTreeView.h.

#include "ProcessTreeView.h"

#include <commctrl.h>

#include "ProcessTree.h"

namespace wintcp {
namespace {

// Longest tree label assembled below. A name plus " (PID 4294967295,
// 18446744073709551615 connections)" cannot reach this; swprintf_s
// truncates rather than overruns in any case.
constexpr size_t kLabelChars = 320;

}  // namespace

size_t ProcessTreeFill(HWND tree, const std::vector<ProcessTreeNode>& procs,
                       bool* depthExceeded) {
    if (tree == nullptr) return 0;
    if (depthExceeded != nullptr) *depthExceeded = false;
    ::SendMessageW(tree, TVM_DELETEITEM, 0,
                   reinterpret_cast<LPARAM>(TVI_ROOT));
    if (procs.empty()) return 0;

    // The engine builds its tree over one TreeNodeInfo per process, indexed
    // by position, so 'procs' order IS the index space here. No aggregation
    // in this module: the caller decides which processes exist and the label
    // names them, so "chrome.exe appears 32 times" is the caller's answer,
    // not a folding rule hidden here.
    std::vector<TreeNodeInfo> infos;
    infos.reserve(procs.size());
    for (const ProcessTreeNode& p : procs) {
        TreeNodeInfo info;
        info.pid = p.pid;
        info.ppid = p.ppid;
        info.ppidKnown = p.ppidKnown;
        infos.push_back(info);
    }
    // A cycle or an over-deep chain is REPORTED by the engine, never thrown:
    // a partially-drawn tree beats no tree, and depthExceeded is shown
    // rather than silently truncating.
    const ProcessTree built = BuildProcessTree(infos);
    if (depthExceeded != nullptr) *depthExceeded = built.depthExceeded;

    ::SendMessageW(tree, WM_SETREDRAW, FALSE, 0);
    for (size_t r = 0; r < built.rootCount && r < built.nodes.size(); ++r) {
        // Iterative descent with the engine's own visited set as the back
        // stop: BuildProcessTree already broke cycles, but a second guard
        // here means a future engine change cannot hang the UI.
        struct Frame {
            size_t node;
            HTREEITEM parent;
            size_t child;
            HTREEITEM self;
            bool entered;
        };
        std::vector<Frame> stack;
        stack.reserve(16);
        stack.push_back(Frame{r, TVI_ROOT, 0, nullptr, false});
        // Guard on node ENTRIES, not loop iterations: every node is entered
        // at most once (each has at most one parent - the engine attaches a
        // child to the first row that claims it, and back-edges into the
        // current stack are refused below), so the ceiling is the node count.
        // An earlier bound counted iterations, and a node with many children
        // spends one iteration per child, so a wide-but-shallow tree (one
        // process, fifty children) could hit it and silently truncate.
        size_t entered = 0;
        const size_t enteredCap = built.nodes.size() + 1;
        while (!stack.empty() && entered < enteredCap) {
            Frame& f = stack.back();
            if (f.node >= built.nodes.size()) {
                stack.pop_back();
                continue;
            }
            const TreeNode& n = built.nodes[f.node];
            if (!f.entered) {
                ++entered;
                f.entered = true;
                const ProcessTreeNode& p =
                    procs[n.rowIndex < procs.size() ? n.rowIndex : 0];
                wchar_t label[kLabelChars] = {0};
                ::swprintf_s(label, L"%ls  (PID %lu, %zu connection%ls)",
                             p.name.c_str(),
                             static_cast<unsigned long>(p.pid),
                             p.connections,
                             (p.connections == 1) ? L"" : L"s");
                TVINSERTSTRUCTW ins = {};
                ins.hParent = f.parent;
                ins.hInsertAfter = TVI_LAST;
                ins.item.mask = TVIF_TEXT | TVIF_PARAM;
                ins.item.pszText = label;
                ins.item.lParam = static_cast<LPARAM>(p.pid);
                f.self = reinterpret_cast<HTREEITEM>(::SendMessageW(
                    tree, TVM_INSERTITEMW, 0,
                    reinterpret_cast<LPARAM>(&ins)));
                if (f.self == nullptr) {
                    stack.pop_back();
                    continue;
                }
            }
            if (f.child < n.children.size()) {
                const size_t next = n.children[f.child];
                ++f.child;
                // Never descend into an ancestor: the engine reports cycles
                // instead of following them, and so does this walk.
                bool backEdge = false;
                for (const Frame& a : stack) {
                    if (a.node == next) {
                        backEdge = true;
                        break;
                    }
                }
                if (!backEdge)
                    stack.push_back(Frame{next, f.self, 0, nullptr, false});
            } else {
                // Roots start expanded one level, so the forest reads as a
                // tree on open rather than a list of roots.
                if (f.parent == TVI_ROOT && f.self != nullptr)
                    ::SendMessageW(tree, TVM_EXPAND,
                                   static_cast<WPARAM>(TVE_EXPAND),
                                   reinterpret_cast<LPARAM>(f.self));
                stack.pop_back();
            }
        }
    }
    ::SendMessageW(tree, WM_SETREDRAW, TRUE, 0);
    ::InvalidateRect(tree, nullptr, TRUE);
    // Preselect the first root, the way Task Manager's Processes tab selects
    // the first process when the tab is switched to. Without a selection the
    // tree is a picture: no caret to move with the arrow keys, no node to
    // map back to a list row, so Details/Copy/Block would all be grey. Do it
    // here, in the shared fill, so both surfaces get it rather than each
    // remembering to.
    {
        const HTREEITEM first = reinterpret_cast<HTREEITEM>(
            ::SendMessageW(tree, TVM_GETNEXTITEM, TVGN_ROOT, 0));
        if (first != nullptr)
            ::SendMessageW(tree, TVM_SELECTITEM, TVGN_CARET,
                           reinterpret_cast<LPARAM>(first));
    }
    return procs.size();
}

}  // namespace wintcp
