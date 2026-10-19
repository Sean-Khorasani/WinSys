// ProcessTreeView.cpp
// SPDX-License-Identifier: Apache-2.0
// See ProcessTreeView.h.

#include "ProcessTreeView.h"

#include <commctrl.h>

#include <unordered_map>

#include "ProcessTree.h"
#include "Connection.h"

namespace wintcp {
namespace {

// Longest tree label assembled below. A name plus " (PID 4294967295,
// 18446744073709551615 connections)" cannot reach this; swprintf_s
// truncates rather than overruns in any case.
constexpr size_t kLabelChars = 320;

struct ProcessLifetimeKey {
    DWORD pid;
    DWORD low;
    DWORD high;

    bool operator==(const ProcessLifetimeKey& other) const {
        return pid == other.pid && low == other.low && high == other.high;
    }
};

struct ProcessLifetimeKeyHash {
    size_t operator()(const ProcessLifetimeKey& key) const {
        size_t value = static_cast<size_t>(key.pid);
        value ^= static_cast<size_t>(key.low) + 0x9e3779b9u + (value << 6) +
                 (value >> 2);
        value ^= static_cast<size_t>(key.high) + 0x9e3779b9u + (value << 6) +
                 (value >> 2);
        return value;
    }
};

bool ProcessLifetimeOf(const ProcessTreeNode& process,
                       ProcessLifetimeKey* key) {
    if (!process.processCreateKnown || key == nullptr) return false;
    key->pid = process.pid;
    key->low = process.processCreate.dwLowDateTime;
    key->high = process.processCreate.dwHighDateTime;
    return true;
}

template <typename Callback>
void ForEachTreeItem(HWND tree, Callback callback) {
    if (tree == nullptr) return;
    std::vector<HTREEITEM> pending;
    for (HTREEITEM root = reinterpret_cast<HTREEITEM>(::SendMessageW(
             tree, TVM_GETNEXTITEM, TVGN_ROOT, 0));
         root != nullptr;
         root = reinterpret_cast<HTREEITEM>(::SendMessageW(
             tree, TVM_GETNEXTITEM, TVGN_NEXT,
             reinterpret_cast<LPARAM>(root)))) {
        pending.push_back(root);
        while (!pending.empty()) {
            const HTREEITEM item = pending.back();
            pending.pop_back();
            callback(item);
            for (HTREEITEM child = reinterpret_cast<HTREEITEM>(::SendMessageW(
                     tree, TVM_GETNEXTITEM, TVGN_CHILD,
                     reinterpret_cast<LPARAM>(item)));
                 child != nullptr;
                 child = reinterpret_cast<HTREEITEM>(::SendMessageW(
                     tree, TVM_GETNEXTITEM, TVGN_NEXT,
                     reinterpret_cast<LPARAM>(child)))) {
                pending.push_back(child);
            }
        }
    }
}

}  // namespace

bool ProcessInstanceMatches(DWORD pid, const FILETIME& processCreate,
                            bool processCreateKnown,
                            const Connection& process) {
    return pid == process.identity.pid && processCreateKnown &&
           process.procMeta.processCreateKnown &&
           ::CompareFileTime(&processCreate,
                             &process.procMeta.processCreate) == 0;
}

const Connection* FindProcessInstance(const std::vector<Connection>& rows,
                                      DWORD pid, const FILETIME& processCreate,
                                      bool processCreateKnown) {
    for (const Connection& row : rows) {
        if ((row.flags & kRowRemoved) == 0 &&
            ProcessInstanceMatches(pid, processCreate, processCreateKnown,
                                   row)) {
            return &row;
        }
    }
    return nullptr;
}

std::optional<size_t> FindProcessTreeViewRow(
    const std::vector<Connection>& rows, const std::vector<size_t>& view,
    const ProcessTreeNode& process) {
    for (size_t viewIndex = 0; viewIndex < view.size(); ++viewIndex) {
        const size_t rowIndex = view[viewIndex];
        if (rowIndex >= rows.size()) continue;
        const Connection& row = rows[rowIndex];
        if ((row.flags & kRowRemoved) == 0 &&
            ProcessTreeMatchesProcess(process, row)) {
            return viewIndex;
        }
    }
    return std::nullopt;
}

bool ProcessTreeMatchesProcess(const ProcessTreeNode& node,
                               const Connection& process) {
    return ProcessInstanceMatches(node.pid, node.processCreate,
                                  node.processCreateKnown, process);
}

bool MakeProcessTreeActionCopy(const ProcessTreeNode& process,
                               const std::vector<Connection>& rows,
                               const Connection* resolvedProcess,
                               Connection& output) {
    if (process.pid == 0 || !process.processCreateKnown) return false;
    for (const Connection& row : rows) {
        if ((row.flags & kRowRemoved) == 0 &&
            ProcessTreeMatchesProcess(process, row)) {
            output = row;
            return true;
        }
    }
    if (resolvedProcess == nullptr ||
        (resolvedProcess->flags & kRowRemoved) != 0 ||
        !ProcessTreeMatchesProcess(process, *resolvedProcess))
        return false;
    output = *resolvedProcess;
    return true;
}

const ProcessTreeNode* ProcessTreeNodeForItemData(
    const std::vector<ProcessTreeNode>& procs, LPARAM itemData) {
    if (itemData < 0) return nullptr;
    const size_t index = static_cast<size_t>(itemData);
    return index < procs.size() ? &procs[index] : nullptr;
}

const ProcessTreeNode* FindProcessTreeInstance(
    const std::vector<ProcessTreeNode>& procs,
    const ProcessTreeNode& captured) {
    if (captured.pid == 0 || !captured.processCreateKnown) return nullptr;
    for (const ProcessTreeNode& process : procs) {
        if (process.pid == captured.pid && process.processCreateKnown &&
            ::CompareFileTime(&process.processCreate,
                              &captured.processCreate) == 0) {
            return &process;
        }
    }
    return nullptr;
}

ProcessTreeViewState CaptureProcessTreeViewState(
    HWND tree, const std::vector<ProcessTreeNode>& procs) {
    ProcessTreeViewState state;
    if (tree == nullptr) return state;
    const HTREEITEM caret = reinterpret_cast<HTREEITEM>(::SendMessageW(
        tree, TVM_GETNEXTITEM, TVGN_CARET, 0));
    ForEachTreeItem(tree, [&](HTREEITEM item) {
        TVITEMW value = {};
        value.mask = TVIF_PARAM | TVIF_STATE | TVIF_HANDLE;
        value.stateMask = TVIS_EXPANDED;
        value.hItem = item;
        if (::SendMessageW(tree, TVM_GETITEMW, 0,
                           reinterpret_cast<LPARAM>(&value)) == 0) {
            return;
        }
        const ProcessTreeNode* process =
            ProcessTreeNodeForItemData(procs, value.lParam);
        if (process == nullptr) return;
        if (item == caret) state.caret = *process;
        ProcessLifetimeKey key = {};
        if (!ProcessLifetimeOf(*process, &key)) return;
        state.expansions.push_back(ProcessTreeExpansionState{
            *process, (value.state & TVIS_EXPANDED) != 0});
    });
    return state;
}

void RestoreProcessTreeViewState(
    HWND tree, const std::vector<ProcessTreeNode>& procs,
    const ProcessTreeViewState& state) {
    if (tree == nullptr) return;
    std::unordered_map<ProcessLifetimeKey, HTREEITEM, ProcessLifetimeKeyHash>
        items;
    items.reserve(procs.size());
    ForEachTreeItem(tree, [&](HTREEITEM item) {
        TVITEMW value = {};
        value.mask = TVIF_PARAM | TVIF_HANDLE;
        value.hItem = item;
        if (::SendMessageW(tree, TVM_GETITEMW, 0,
                           reinterpret_cast<LPARAM>(&value)) == 0) {
            return;
        }
        const ProcessTreeNode* process =
            ProcessTreeNodeForItemData(procs, value.lParam);
        ProcessLifetimeKey key = {};
        if (process != nullptr && ProcessLifetimeOf(*process, &key))
            items.emplace(key, item);
    });
    for (const ProcessTreeExpansionState& expansion : state.expansions) {
        ProcessLifetimeKey key = {};
        if (!ProcessLifetimeOf(expansion.process, &key)) continue;
        const auto found = items.find(key);
        if (found == items.end()) continue;
        ::SendMessageW(tree, TVM_EXPAND,
                       expansion.expanded ? TVE_EXPAND : TVE_COLLAPSE,
                       reinterpret_cast<LPARAM>(found->second));
    }
    if (state.caret.has_value()) {
        ProcessLifetimeKey key = {};
        if (ProcessLifetimeOf(*state.caret, &key)) {
            const auto found = items.find(key);
            if (found != items.end()) {
                ::SendMessageW(tree, TVM_SELECTITEM, TVGN_CARET,
                               reinterpret_cast<LPARAM>(found->second));
            }
        }
    }
}

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
                ins.item.lParam = static_cast<LPARAM>(n.rowIndex);
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
