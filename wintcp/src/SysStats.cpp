// SysStats.cpp
// SPDX-License-Identifier: Apache-2.0
// See SysStats.h. Same sampling math as ChartsWindow::Sample, minus the
// window, the histories and the painting.

// ws2tcpip.h must come first: netioapi.h only declares MIB_IF_ROW2 and
// GetIfTable2() when _WS2IPDEF_ (from ws2ipdef.h) is already defined.
#include <winsock2.h>
#include <ws2tcpip.h>

#include "SysStats.h"

#include "WinCaps.h"   // DllAvailable: pdh.dll is delay-loaded (see kDelayedDlls)

#include <iphlpapi.h>
#include <netioapi.h>
#include <pdh.h>
#include <pdhmsg.h>

namespace wintcp {
namespace {

ULONGLONG FtToU64(const FILETIME& ft) {
    ULARGE_INTEGER u = {};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

constexpr ULONG kIfTypeSoftwareLoopback = 24;

// Percentages are reported on a 0..100 scale so a value is renderable as-is.
// Same name as ProcStats.cpp's copy on purpose - a grep should find both.
constexpr double kPctScale = 100.0;

// Ticks of the sampler loop to wait before re-opening a failed PDH disk
// query. Same value and reasoning as ChartsWindow.cpp's same-named constant
// (both loops tick at ~1 s, so 10 is ~10 s of silence): the two must stay in
// step, and the name is identical on purpose so a grep finds both.
constexpr int kPdhReopenRetryTicks = 10;

}  // namespace

SystemStatsSampler::SystemStatsSampler() = default;

SystemStatsSampler::~SystemStatsSampler() { CleanupPdh(); }

void SystemStatsSampler::CleanupPdh() {
    if (pdhQuery_ != nullptr) {
        ::PdhCloseQuery(static_cast<HQUERY>(pdhQuery_));
        pdhQuery_ = nullptr;
        pdhRead_ = nullptr;
        pdhWrite_ = nullptr;
    }
}

void SystemStatsSampler::Clear() {
    haveCpuBase_ = false;
    haveNetBase_ = false;
    pdhRetryIn_ = 0;
    pdhFails_ = 0;
    CleanupPdh();
}

SystemStats SystemStatsSampler::Sample() {
    SystemStats s;
    const ULONGLONG nowTick = ::GetTickCount64();
    s.netTickMs = nowTick;

    // --- CPU (GetSystemTimes) ---
    FILETIME idle = {}, kernel = {}, user = {};
    if (::GetSystemTimes(&idle, &kernel, &user)) {
        if (haveCpuBase_) {
            const ULONGLONG idleD = FtToU64(idle) - FtToU64(prevIdle_);
            const ULONGLONG totalD = (FtToU64(kernel) - FtToU64(prevKernel_)) +
                                     (FtToU64(user) - FtToU64(prevUser_));
            if (totalD > 0) {
                double busy = 1.0 - static_cast<double>(idleD) /
                                        static_cast<double>(totalD);
                if (busy < 0.0) busy = 0.0;
                if (busy > 1.0) busy = 1.0;
                s.cpuKnown = true;
                s.cpuPct = busy * kPctScale;
            }
        }
        prevIdle_ = idle;
        prevKernel_ = kernel;
        prevUser_ = user;
        haveCpuBase_ = true;
    }

    // --- memory ---
    MEMORYSTATUSEX ms = {};
    ms.dwLength = sizeof(ms);
    if (::GlobalMemoryStatusEx(&ms) && ms.ullTotalPhys > 0) {
        s.memKnown = true;
        s.memTotal = ms.ullTotalPhys;
        s.memUsed = ms.ullTotalPhys - ms.ullAvailPhys;
        s.memPct = kPctScale * static_cast<double>(s.memUsed) /
                   static_cast<double>(s.memTotal);
    }

    // --- disk (PDH PhysicalDisk _Total, best effort) ---
    //
    // The DllAvailable gate is not optional and not decoration. pdh.dll is
    // delay-loaded (see kDelayedDlls in WinCaps.cpp), and a delay-loaded
    // import resolves on FIRST CALL - so without this check, a machine with no
    // pdh.dll would take a delay-load EXCEPTION here instead of reporting that
    // the disk figures are unavailable. The gate turns that crash into the
    // known=false below, which is what the caller already knows how to render.
    // Same pattern as SocketTrafficSampler::Supported().
    if (pdhQuery_ == nullptr && DllAvailable("pdh.dll")) {
        if (pdhRetryIn_ <= 0) {
            HQUERY q = nullptr;
            HCOUNTER rd = nullptr, wr = nullptr;
            if (::PdhOpenQueryW(nullptr, 0, &q) == ERROR_SUCCESS &&
                ::PdhAddEnglishCounterW(
                    q, L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
                    0, &rd) == ERROR_SUCCESS &&
                ::PdhAddEnglishCounterW(
                    q, L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec",
                    0, &wr) == ERROR_SUCCESS &&
                ::PdhCollectQueryData(q) == ERROR_SUCCESS) {
                pdhQuery_ = q;
                pdhRead_ = rd;
                pdhWrite_ = wr;
                pdhFails_ = 0;
            } else {
                if (q != nullptr) ::PdhCloseQuery(q);
                pdhRetryIn_ = kPdhReopenRetryTicks;
            }
        } else {
            --pdhRetryIn_;
        }
    }
    if (pdhQuery_ != nullptr) {
        bool ok = ::PdhCollectQueryData(static_cast<HQUERY>(pdhQuery_)) ==
                  ERROR_SUCCESS;
        PDH_FMT_COUNTERVALUE fv = {};
        double rd = 0.0, wr = 0.0;
        if (ok && ::PdhGetFormattedCounterValue(static_cast<HCOUNTER>(pdhRead_),
                                                PDH_FMT_DOUBLE, nullptr,
                                                &fv) == ERROR_SUCCESS &&
            fv.CStatus == ERROR_SUCCESS) {
            rd = (fv.doubleValue < 0.0) ? 0.0 : fv.doubleValue;
        } else {
            ok = false;
        }
        if (ok && ::PdhGetFormattedCounterValue(static_cast<HCOUNTER>(pdhWrite_),
                                                PDH_FMT_DOUBLE, nullptr,
                                                &fv) == ERROR_SUCCESS &&
            fv.CStatus == ERROR_SUCCESS) {
            wr = (fv.doubleValue < 0.0) ? 0.0 : fv.doubleValue;
        } else {
            ok = false;
        }
        if (ok) {
            pdhFails_ = 0;
            s.diskKnown = true;
            s.diskReadBps = rd;
            s.diskWriteBps = wr;
        } else if (++pdhFails_ >= 3) {
            CleanupPdh();
            pdhRetryIn_ = kPdhReopenRetryTicks;
        }
    }

    // --- network (GetIfTable2 octet deltas, loopback excluded) ---
    PMIB_IF_TABLE2 ifTable = nullptr;
    if (::GetIfTable2(&ifTable) == NO_ERROR && ifTable != nullptr) {
        ULONGLONG inOctets = 0;
        ULONGLONG outOctets = 0;
        for (ULONG i = 0; i < ifTable->NumEntries; ++i) {
            const MIB_IF_ROW2& row = ifTable->Table[i];
            if (row.Type == kIfTypeSoftwareLoopback) continue;
            inOctets += row.InOctets;
            outOctets += row.OutOctets;
        }
        ::FreeMibTable(ifTable);
        if (haveNetBase_ && nowTick > prevNetTick_) {
            const double dt =
                static_cast<double>(nowTick - prevNetTick_) / 1000.0;
            if (dt > 0.0) {
                s.netKnown = true;
                s.netRecvBps = (inOctets >= prevNetIn_)
                    ? static_cast<double>(inOctets - prevNetIn_) / dt
                    : 0.0;
                s.netSendBps = (outOctets >= prevNetOut_)
                    ? static_cast<double>(outOctets - prevNetOut_) / dt
                    : 0.0;
            }
        }
        prevNetIn_ = inOctets;
        prevNetOut_ = outOctets;
        prevNetTick_ = nowTick;
        haveNetBase_ = true;
    }

    return s;
}

}  // namespace wintcp
