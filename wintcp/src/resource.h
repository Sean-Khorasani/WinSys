// resource.h
// SPDX-License-Identifier: Apache-2.0
// Control / menu / icon identifiers for wintcp.

#pragma once

#define IDI_APP                 100

#define IDR_MAINMENU            1000
#define IDR_ACCEL               1001

#define IDC_LIST                1100
#define IDC_STATUS              1101
#define IDC_BTN_REFRESH         1102
#define IDC_BTN_EXPORT          1103
#define IDC_CHK_AUTOREFRESH     1104
#define IDC_CBO_INTERVAL        1105
#define IDC_CBO_PROTO           1106
#define IDC_CBO_STATE           1107
#define IDC_EDIT_SEARCH         1108
#define IDC_STATIC_FILTER       1109
#define IDC_STATIC_PROTO        1110
#define IDC_STATIC_STATE        1111
// The tree control that replaces the list in process-tree mode.
// Same client area, one visible at a time.
#define IDC_PROCESS_TREE        1112

#define IDM_FILE_REFRESH        40001
#define IDM_FILE_EXPORT         40002
#define IDM_FILE_EXIT           40003
#define IDM_VIEW_AUTOREFRESH    40004
#define IDM_HELP_ABOUT          40005
#define IDM_VIEW_RESOLVE        40006
#define IDM_EDIT_SELECTALL      40007
#define IDM_EDIT_FOCUSFILTER    40008
#define IDM_EDIT_CLEARFILTER    40009
#define IDM_FILE_CHANGELOG      40010
#define IDM_CTX_EXPORT_SELECTION 40011
// 40012 was IDM_VIEW_DARK; the app now follows the system theme instead of
// offering a dark-mode toggle. The slot stays reserved so the remaining
// command IDs keep their values.
#define IDM_VIEW_TRAY           40013
#define IDM_VIEW_TOPMOST        40014
#define IDM_TRAY_RESTORE        40015
#define IDM_VIEW_TRAFFIC        40016
#define IDM_VIEW_CHARTS         40017

// Placed after the existing View ids so no existing command number
// shifts - renumbering them would break any accelerator table referring to
// them by literal value.
#define IDM_VIEW_PRESERVE_SEL   40018

// Freeze and grouping. After the existing View ids so no existing
// command number shifts.
#define IDM_VIEW_FREEZE         40019
#define IDM_VIEW_GROUP          40020

// The shortcuts sheet, and the About box split out so F1 can open
// the sheet while the About dialog keeps its own command id.
#define IDM_HELP_SHORTCUTS      40021
#define IDM_VIEW_GEOIP          40022
// The firewall viewer. Reads the rules `blocks` counts. 40065 because
// 40023 is IDM_FILE_PRESET_SAVE - the View ids are not a contiguous block, and
// a duplicate #define is a silently-shadowed menu command.
#define IDM_VIEW_BLOCKED        40065
// Offers the buttons for whatever empty state the table is in. Always
// enabled; when there is nothing to fix it says so, which is itself the answer
// to "why is my table empty" being asked at all. 40066 keeps it beside the
// other View ids; 40200 is IDM_COL_BASE and must stay the boundary.
#define IDM_VIEW_FIX_EMPTY      40066
#define IDM_VIEW_ASNIP          40040
// One-click recovery for a mangled column layout. Beside the other View
// ids; 40067/40068 are free (the column block starts at 40200).
#define IDM_VIEW_RESET_LAYOUT   40067
// GUI process-tree view: a tree control over the same snapshot the list
// shows. The engine (ProcessTree) and the killtree verb already shipped;
// this is the view chrome over them.
#define IDM_VIEW_PROCESSTREE    40068

// Column profiles and quick filters. Appended after the
// highest in-use View id so no existing command number shifts - the same rule
// the View block above follows.
//
// The five profiles are a CONTIGUOUS block (40041..40045) because the handler
// resolves them arithmetically, and a gap there would silently turn an entry
// into the wrong profile rather than failing to compile.
#define IDM_PROFILE_DEFAULT     40041
#define IDM_PROFILE_MINIMAL     40042
#define IDM_PROFILE_NETWORK     40043
#define IDM_PROFILE_SECURITY    40044
#define IDM_PROFILE_PERFORMANCE 40045
#define IDM_PROFILE_DIAGNOSTICS 40046

// One-click quick filters. A contiguous block too, for the same reason:
// the handler indexes a table by the offset from the first id.
#define IDM_QFILTER_ALL         40047
#define IDM_QFILTER_TCP         40048
#define IDM_QFILTER_UDP         40049
#define IDM_QFILTER_LISTEN      40050
#define IDM_QFILTER_ESTAB       40051
#define IDM_QFILTER_MINE        40052
#define IDM_QFILTER_CLEAR       40053

// Preset and bookmark commands, wired into the GUI.
#define IDM_FILE_PRESET_SAVE    40023
#define IDM_FILE_PRESET_LOAD    40024
#define IDM_FILE_PRESET_DELETE  40025
#define IDM_FILE_BOOKMARKS      40026
#define IDM_CTX_BOOKMARK        40027
#define IDM_CTX_NOTE            40028
#define IDM_FILE_CHANGELOG_WIN  40029

#define IDM_CTX_COPY_SELECTED   40101
#define IDM_CTX_COPY_ALL        40102
#define IDM_CTX_DETAILS         40103
#define IDM_CTX_KILL_PROCESS    40104
#define IDM_CTX_REFRESH         40105
#define IDM_CTX_CLOSE_CONNECTION 40106
#define IDM_CTX_COPY_REMOTE_IP  40107
#define IDM_CTX_COPY_HOSTNAME   40108
#define IDM_CTX_COPY_LOCAL_ENDPOINT 40109
#define IDM_CTX_COPY_REMOTE_ENDPOINT 40110
#define IDM_CTX_COPY_PROCESS_PATH 40111
#define IDM_CTX_COPY_PROCESS_ID 40112
#define IDM_CTX_COPY_LOCAL_PORT 40113
#define IDM_CTX_COPY_REMOTE_PORT 40114

// Column-visibility menu: one item per ColumnId, in order.
#define IDM_COL_BASE            40200
#define IDM_COL_PROTO           (IDM_COL_BASE + 0)
#define IDM_COL_LOCAL           (IDM_COL_BASE + 1)
#define IDM_COL_LPORT           (IDM_COL_BASE + 2)
#define IDM_COL_REMOTE          (IDM_COL_BASE + 3)
#define IDM_COL_RPORT           (IDM_COL_BASE + 4)
#define IDM_COL_STATE           (IDM_COL_BASE + 5)
#define IDM_COL_PID             (IDM_COL_BASE + 6)
#define IDM_COL_PROCESS         (IDM_COL_BASE + 7)
#define IDM_COL_SERVICE         (IDM_COL_BASE + 8)
#define IDM_COL_HOST            (IDM_COL_BASE + 9)
#define IDM_COL_PATH            (IDM_COL_BASE + 10)
#define IDM_COL_TRAFFIC         (IDM_COL_BASE + 11)
#define IDM_COL_RX              (IDM_COL_BASE + 12)
#define IDM_COL_TX              (IDM_COL_BASE + 13)
#define IDM_COL_NETTOTAL        (IDM_COL_BASE + 14)
#define IDM_COL_CPU             (IDM_COL_BASE + 15)
#define IDM_COL_MEM             (IDM_COL_BASE + 16)
#define IDM_COL_DISK            (IDM_COL_BASE + 17)
#define IDM_COL_DURATION        (IDM_COL_BASE + 18)
#define IDM_COL_BANDWIDTH       (IDM_COL_BASE + 19)
#define IDM_COL_TLS             (IDM_COL_BASE + 20)
#define IDM_COL_COUNTRY         (IDM_COL_BASE + 21)
#define IDM_COL_PINNED          (IDM_COL_BASE + 22)
// The `ss -i` columns, and the per-process rate. Appended, never
// renumbered - the ordinal is baked into nothing persistent, but keeping the
// existing values stable means a diff of this file shows only additions.
#define IDM_COL_RTT             (IDM_COL_BASE + 23)
#define IDM_COL_MINRTT          (IDM_COL_BASE + 24)
#define IDM_COL_CWND            (IDM_COL_BASE + 25)
#define IDM_COL_RETRANS         (IDM_COL_BASE + 26)
#define IDM_COL_GROUPRATE       (IDM_COL_BASE + 27)
// The bookmark note as its own column.
#define IDM_COL_NOTE            (IDM_COL_BASE + 28)
// The parent id, the mandatory integrity level and the
// Authenticode verdict. Appended, never renumbered, for the reason the block
// above gives.
#define IDM_COL_PPID            (IDM_COL_BASE + 29)
#define IDM_COL_INTEGRITY       (IDM_COL_BASE + 30)
#define IDM_COL_SIGNATURE       (IDM_COL_BASE + 31)
// One past the last column command. Checked against COL_COUNT at compile
// time in MainWindow.cpp so a column added without a menu entry is an error
// rather than a checkbox that never appears.
#define IDM_COL_COUNT           32

// Row context menu. Placed after the column block so the
// IDM_COL_BASE..+COUNT range check cannot swallow it.
#define IDM_FOLLOW_STREAM       40060
#define IDM_OPEN_FILE_LOCATION  40061
#define IDM_PROCESS_PROPERTIES  40062
#define IDM_BLOCK_CONNECTION    40063
// Tray menu - remove every rule `block` ever created (the item the
// Block confirmation has always pointed at; it did not exist until now).
#define IDM_TRAY_UNBLOCK_ALL   40064

#define IDS_APP_TITLE           50000
