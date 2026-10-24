// RestrictionWfp.cpp
// SPDX-License-Identifier: Apache-2.0
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <objbase.h>
#include <sddl.h>
#include <tlhelp32.h>

#include "RestrictionWfp.h"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <vector>

namespace wintcp {
namespace {

struct ScopedHandle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit ScopedHandle(HANDLE handle) : value(handle) {}
    ~ScopedHandle() {
        if (value != nullptr && value != INVALID_HANDLE_VALUE) ::CloseHandle(value);
    }
    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;
};

void Fail(std::string* error, const char* code, DWORD result = 0) {
    if (error != nullptr)
        *error = std::string(code) + (result ? ":" + std::to_string(result) : "");
}

bool WideUtf8(const std::string& input, std::wstring* output) {
    if (output == nullptr || input.empty()) return false;
    const int length = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (length <= 0) return false;
    output->resize(static_cast<std::size_t>(length));
    return ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        input.data(), static_cast<int>(input.size()), &(*output)[0], length) == length;
}

bool Elevated() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation = {};
    DWORD size = 0;
    const bool result = ::GetTokenInformation(token, TokenElevation,
        &elevation, sizeof(elevation), &size) != FALSE &&
        elevation.TokenIsElevated != 0;
    ::CloseHandle(token);
    return result;
}

bool ReviewRunningProcesses(const std::wstring& path, const std::wstring& sid,
                            std::string* error) {
    using InformationFn = BOOL (WINAPI*)(HANDLE, int, void*, DWORD);
    using CriticalFn = BOOL (WINAPI*)(HANDLE, PBOOL);
    const HMODULE kernel = ::GetModuleHandleW(L"kernel32.dll");
    const auto information = reinterpret_cast<InformationFn>(
        ::GetProcAddress(kernel, "GetProcessInformation"));
    const auto critical = reinterpret_cast<CriticalFn>(
        ::GetProcAddress(kernel, "IsProcessCritical"));
    if (information == nullptr || critical == nullptr) {
        Fail(error, "process_protection_query_unavailable");
        return false;
    }
    PSID approvedSid = nullptr;
    if (!::ConvertStringSidToSidW(sid.c_str(), &approvedSid)) {
        Fail(error, "invalid_user_sid");
        return false;
    }
    const std::wstring filename = path.substr(path.find_last_of(L'\\') + 1);
    ScopedHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.value == INVALID_HANDLE_VALUE) {
        ::LocalFree(approvedSid);
        Fail(error, "process_inventory_unavailable");
        return false;
    }
    bool valid = true;
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (!::Process32FirstW(snapshot.value, &entry)) {
        ::LocalFree(approvedSid);
        Fail(error, "process_inventory_unavailable");
        return false;
    }
    do {
        if (::CompareStringOrdinal(entry.szExeFile, -1, filename.c_str(), -1,
                                   TRUE) != CSTR_EQUAL) continue;
        ScopedHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                           SYNCHRONIZE, FALSE, entry.th32ProcessID));
        if (process.value == nullptr) {
            Fail(error, "target_process_identity_unavailable"); valid = false; break;
        }
        wchar_t image[32768] = {};
        DWORD length = 32768;
        if (!::QueryFullProcessImageNameW(process.value, 0, image, &length)) {
            if (::WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0) continue;
            Fail(error, "target_process_identity_unavailable"); valid = false; break;
        }
        if (::CompareStringOrdinal(image, -1, path.c_str(), -1, TRUE) != CSTR_EQUAL)
            continue;
        FILETIME created = {}, exited = {}, kernelTime = {}, userTime = {};
        DWORD protection = 0;
        BOOL isCritical = TRUE;
        // Documented ProcessProtectionLevelInfo (SDK enum value 7), dynamically
        // resolved to preserve the portable executable's older import floor.
        if (!::GetProcessTimes(process.value, &created, &exited, &kernelTime, &userTime) ||
            (created.dwLowDateTime == 0 && created.dwHighDateTime == 0) ||
            !information(process.value, 7, &protection, sizeof(protection)) ||
            !critical(process.value, &isCritical)) {
            if (::WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0) continue;
            Fail(error, "target_process_identity_unavailable"); valid = false; break;
        }
        if (protection != 0xfffffffeUL || isCritical) {
            Fail(error, "protected_target_refused"); valid = false; break;
        }
        HANDLE rawToken = nullptr;
        if (!::OpenProcessToken(process.value, TOKEN_QUERY, &rawToken)) {
            Fail(error, "target_user_unavailable"); valid = false; break;
        }
        ScopedHandle token(rawToken);
        DWORD bytes = 0;
        (void)::GetTokenInformation(token.value, TokenUser, nullptr, 0, &bytes);
        if (bytes == 0 || bytes > 65536) {
            Fail(error, "target_user_unavailable"); valid = false; break;
        }
        std::vector<unsigned char> data(bytes);
        if (!::GetTokenInformation(token.value, TokenUser, data.data(), bytes, &bytes) ||
            !::EqualSid(reinterpret_cast<const TOKEN_USER*>(data.data())->User.Sid,
                        approvedSid)) {
            Fail(error, "target_user_mismatch"); valid = false; break;
        }
    } while (::Process32NextW(snapshot.value, &entry));
    if (valid && ::GetLastError() != ERROR_NO_MORE_FILES) {
        Fail(error, "process_inventory_incomplete");
        valid = false;
    }
    ::LocalFree(approvedSid);
    return valid;
}

}  // namespace

bool ReviewRestrictionTarget(const RestrictionPlan& plan, std::string* error,
                             std::string* fileIdentity, HANDLE* lockedFile) {
    if (lockedFile != nullptr) *lockedFile = INVALID_HANDLE_VALUE;
    if (error == nullptr || !ValidateRestrictionPlan(plan, error)) return false;
    std::wstring path;
    if (!WideUtf8(plan.imagePath, &path)) {
        Fail(error, "invalid_encoding");
        return false;
    }
    const DWORD attributes = ::GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
        Fail(error, "target_executable_unavailable");
        return false;
    }
    ScopedHandle file(::CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (file.value == INVALID_HANDLE_VALUE) {
        Fail(error, "target_identity_unavailable");
        return false;
    }
    std::wstring finalPath(32768, L'\0');
    const DWORD finalLength = ::GetFinalPathNameByHandleW(file.value, &finalPath[0],
        static_cast<DWORD>(finalPath.size()), FILE_NAME_NORMALIZED);
    if (finalLength < 4 || finalLength >= finalPath.size()) {
        Fail(error, "target_identity_unavailable");
        return false;
    }
    finalPath.resize(finalLength);
    if (finalPath.compare(0, 4, L"\\\\?\\") != 0) {
        Fail(error, "target_identity_unavailable");
        return false;
    }
    finalPath.erase(0, 4);
    if (::CompareStringOrdinal(path.c_str(), -1, finalPath.c_str(), -1,
                               TRUE) != CSTR_EQUAL) {
        Fail(error, "image_path_not_final");
        return false;
    }
    wchar_t ownPath[32768] = {};
    const DWORD ownLength = ::GetModuleFileNameW(nullptr, ownPath, 32768);
    if (ownLength == 0 || ownLength >= 32768 ||
        ::CompareStringOrdinal(path.c_str(), -1, ownPath, -1, TRUE) == CSTR_EQUAL) {
        Fail(error, "collector_self_target_refused");
        return false;
    }
    wchar_t windowsPath[32768] = {};
    const UINT windowsLength = ::GetWindowsDirectoryW(windowsPath, 32768);
    if (windowsLength == 0 || windowsLength >= 32768) {
        Fail(error, "system_path_unavailable");
        return false;
    }
    std::wstring prefix(windowsPath, windowsLength);
    if (!prefix.empty() && prefix.back() != L'\\') prefix += L'\\';
    if (path.size() >= prefix.size() &&
        ::CompareStringOrdinal(path.c_str(), static_cast<int>(prefix.size()),
                               prefix.c_str(), static_cast<int>(prefix.size()),
                               TRUE) == CSTR_EQUAL) {
        Fail(error, "system_target_refused");
        return false;
    }
    BY_HANDLE_FILE_INFORMATION info = {};
    if (!::GetFileInformationByHandle(file.value, &info)) {
        Fail(error, "target_identity_unavailable");
        return false;
    }
    const std::string identity = std::to_string(info.dwVolumeSerialNumber) + ':' +
        std::to_string(info.nFileIndexHigh) + ':' + std::to_string(info.nFileIndexLow) + ':' +
        std::to_string(info.nFileSizeHigh) + ':' + std::to_string(info.nFileSizeLow) + ':' +
        std::to_string(info.ftLastWriteTime.dwHighDateTime) + ':' +
        std::to_string(info.ftLastWriteTime.dwLowDateTime);
    if (!plan.imageFileIdentity.empty() && identity != plan.imageFileIdentity) {
        Fail(error, "target_file_changed_since_preview");
        return false;
    }
    ScopedHandle ownFile(::CreateFileW(ownPath, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    BY_HANDLE_FILE_INFORMATION ownInfo = {};
    if (ownFile.value == INVALID_HANDLE_VALUE ||
        !::GetFileInformationByHandle(ownFile.value, &ownInfo)) {
        Fail(error, "collector_identity_unavailable");
        return false;
    }
    if (ownInfo.dwVolumeSerialNumber == info.dwVolumeSerialNumber &&
        ownInfo.nFileIndexHigh == info.nFileIndexHigh &&
        ownInfo.nFileIndexLow == info.nFileIndexLow) {
        Fail(error, "collector_self_target_refused");
        return false;
    }
    std::wstring sid;
    if (!WideUtf8(plan.userSid, &sid) || !ReviewRunningProcesses(path, sid, error))
        return false;
    if (fileIdentity != nullptr) *fileIdentity = identity;
    if (lockedFile != nullptr) {
        *lockedFile = file.value;
        file.value = INVALID_HANDLE_VALUE;
    }
    error->clear();
    return true;
}

DynamicWfpSession::~DynamicWfpSession() { Close(); }

void DynamicWfpSession::Close() {
    if (engine_ != nullptr) {
        (void)::FwpmEngineClose0(engine_);
        engine_ = nullptr;
    }
    owned_.clear();
}

bool DynamicWfpSession::Open(std::string* error) {
    if (engine_ != nullptr) { if (error) error->clear(); return true; }
    if (!Elevated()) { Fail(error, "elevation_required"); return false; }
    FWPM_SESSION0 session = {};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name = const_cast<wchar_t*>(L"WinTCP temporary restrictions");
    DWORD result = ::FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr,
                                     &session, &engine_);
    if (result != ERROR_SUCCESS) {
        engine_ = nullptr;
        Fail(error, "wfp_open_failed", result);
        return false;
    }
    if (FAILED(::CoCreateGuid(&providerKey_)) ||
        FAILED(::CoCreateGuid(&subLayerKey_))) {
        Fail(error, "wfp_identity_failed");
        Close();
        return false;
    }
    result = ::FwpmTransactionBegin0(engine_, 0);
    if (result != ERROR_SUCCESS) {
        Fail(error, "wfp_transaction_failed", result);
        Close();
        return false;
    }
    FWPM_PROVIDER0 provider = {};
    provider.providerKey = providerKey_;
    provider.displayData.name = const_cast<wchar_t*>(L"WinTCP temporary restriction session");
    result = ::FwpmProviderAdd0(engine_, &provider, nullptr);
    if (result == ERROR_SUCCESS) {
        FWPM_SUBLAYER0 layer = {};
        layer.subLayerKey = subLayerKey_;
        layer.providerKey = &providerKey_;
        layer.displayData.name = const_cast<wchar_t*>(L"WinTCP temporary outbound restrictions");
        layer.weight = 0x7fff;
        result = ::FwpmSubLayerAdd0(engine_, &layer, nullptr);
    }
    if (result == ERROR_SUCCESS) result = ::FwpmTransactionCommit0(engine_);
    else (void)::FwpmTransactionAbort0(engine_);
    if (result != ERROR_SUCCESS) {
        Fail(error, "wfp_session_setup_failed", result);
        Close();
        return false;
    }
    if (error) error->clear();
    return true;
}

bool DynamicWfpSession::Apply(const RestrictionPlan& plan,
                              std::vector<std::uint64_t>* filterIds,
                              std::string* error) {
    if (filterIds == nullptr || error == nullptr) return false;
    filterIds->clear();
    if (engine_ == nullptr) { Fail(error, "wfp_session_closed"); return false; }
    if (plan.imageFileIdentity.empty()) {
        Fail(error, "target_identity_not_approved");
        return false;
    }
    HANDLE pinned = INVALID_HANDLE_VALUE;
    if (!ReviewRestrictionTarget(plan, error, nullptr, &pinned)) return false;
    ScopedHandle pinnedFile(pinned);
    std::wstring path, sid;
    if (!WideUtf8(plan.imagePath, &path) || !WideUtf8(plan.userSid, &sid)) {
        Fail(error, "invalid_encoding");
        return false;
    }
    FWP_BYTE_BLOB* appId = nullptr;
    DWORD result = ::FwpmGetAppIdFromFileName0(path.c_str(), &appId);
    if (result != ERROR_SUCCESS || appId == nullptr) {
        Fail(error, "wfp_app_identity_failed", result);
        return false;
    }
    wchar_t rights[24] = {};
    std::swprintf(rights, sizeof(rights) / sizeof(rights[0]), L"0x%08lx",
                  static_cast<unsigned long>(FWP_ACTRL_MATCH_FILTER));
    const std::wstring sddl = L"D:P(A;;" + std::wstring(rights) + L";;;" + sid + L")";
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
        ::FwpmFreeMemory0(reinterpret_cast<void**>(&appId));
        Fail(error, "wfp_user_scope_failed", ::GetLastError());
        return false;
    }
    FWP_BYTE_BLOB userBlob = {};
    userBlob.data = static_cast<unsigned char*>(descriptor);
    userBlob.size = ::GetSecurityDescriptorLength(descriptor);
    IN_ADDR address4 = {};
    IN6_ADDR address6 = {};
    const bool peer4 = !plan.remoteAddress.empty() &&
        ::InetPtonA(AF_INET, plan.remoteAddress.c_str(), &address4) == 1;
    const bool peer6 = !plan.remoteAddress.empty() && !peer4 &&
        ::InetPtonA(AF_INET6, plan.remoteAddress.c_str(), &address6) == 1;
    FWP_BYTE_ARRAY16 ip6 = {};
    if (peer6) std::memcpy(ip6.byteArray16, &address6, 16);
    const bool use4 = plan.remoteAddress.empty() || peer4;
    const bool use6 = plan.remoteAddress.empty() || peer6;
    const bool useTcp = plan.protocol != RestrictionProtocol::Udp;
    const bool useUdp = plan.protocol != RestrictionProtocol::Tcp;
    const std::size_t count = (static_cast<std::size_t>(use4) + use6) *
        (static_cast<std::size_t>(useTcp) + useUdp);
    if ((!use4 && !use6) || owned_.size() + count > 512) {
        ::LocalFree(descriptor);
        ::FwpmFreeMemory0(reinterpret_cast<void**>(&appId));
        Fail(error, "wfp_filter_capacity_or_peer_invalid");
        return false;
    }
    result = ::FwpmTransactionBegin0(engine_, 0);
    if (result != ERROR_SUCCESS) {
        ::LocalFree(descriptor);
        ::FwpmFreeMemory0(reinterpret_cast<void**>(&appId));
        Fail(error, "wfp_transaction_failed", result);
        return false;
    }
    std::vector<std::uint64_t> created;
    for (int family = 0; family < 2 && result == ERROR_SUCCESS; ++family) {
        if ((family == 0 && !use4) || (family == 1 && !use6)) continue;
        for (int transport = 0; transport < 2 && result == ERROR_SUCCESS; ++transport) {
            if ((transport == 0 && !useTcp) || (transport == 1 && !useUdp)) continue;
            FWPM_FILTER_CONDITION0 conditions[5] = {};
            unsigned n = 0;
            conditions[n].fieldKey = FWPM_CONDITION_ALE_APP_ID;
            conditions[n].matchType = FWP_MATCH_EQUAL;
            conditions[n].conditionValue.type = FWP_BYTE_BLOB_TYPE;
            conditions[n++].conditionValue.byteBlob = appId;
            conditions[n].fieldKey = FWPM_CONDITION_ALE_USER_ID;
            conditions[n].matchType = FWP_MATCH_EQUAL;
            conditions[n].conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
            conditions[n++].conditionValue.sd = &userBlob;
            conditions[n].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            conditions[n].matchType = FWP_MATCH_EQUAL;
            conditions[n].conditionValue.type = FWP_UINT8;
            conditions[n++].conditionValue.uint8 = static_cast<UINT8>(
                transport == 0 ? IPPROTO_TCP : IPPROTO_UDP);
            if (!plan.remoteAddress.empty()) {
                conditions[n].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                conditions[n].matchType = FWP_MATCH_EQUAL;
                if (family == 0) {
                    conditions[n].conditionValue.type = FWP_UINT32;
                    conditions[n].conditionValue.uint32 = ::ntohl(address4.S_un.S_addr);
                } else {
                    conditions[n].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
                    conditions[n].conditionValue.byteArray16 = &ip6;
                }
                ++n;
            }
            if (plan.remotePort != 0) {
                conditions[n].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                conditions[n].matchType = FWP_MATCH_EQUAL;
                conditions[n].conditionValue.type = FWP_UINT16;
                conditions[n++].conditionValue.uint16 = plan.remotePort;
            }
            FWPM_FILTER0 filter = {};
            filter.providerKey = &providerKey_;
            filter.subLayerKey = subLayerKey_;
            filter.layerKey = family == 0 ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 :
                                           FWPM_LAYER_ALE_AUTH_CONNECT_V6;
            filter.displayData.name = const_cast<wchar_t*>(L"WinTCP temporary outbound block");
            filter.action.type = FWP_ACTION_BLOCK;
            filter.weight.type = FWP_UINT8;
            filter.weight.uint8 = 15;
            filter.numFilterConditions = n;
            filter.filterCondition = conditions;
            std::uint64_t id = 0;
            result = ::FwpmFilterAdd0(engine_, &filter, nullptr, &id);
            if (result == ERROR_SUCCESS) created.push_back(id);
        }
    }
    if (result == ERROR_SUCCESS) result = ::FwpmTransactionCommit0(engine_);
    else (void)::FwpmTransactionAbort0(engine_);
    ::LocalFree(descriptor);
    ::FwpmFreeMemory0(reinterpret_cast<void**>(&appId));
    if (result != ERROR_SUCCESS) {
        Fail(error, "wfp_filter_install_failed", result);
        // A failed commit has an uncertain disposition. Closing the dynamic
        // session guarantees no filter from this session survives the failure.
        Close();
        return false;
    }
    for (std::uint64_t id : created) {
        FWPM_FILTER0* installed = nullptr;
        result = ::FwpmFilterGetById0(engine_, id, &installed);
        const bool verified = result == ERROR_SUCCESS && installed != nullptr &&
            installed->action.type == FWP_ACTION_BLOCK;
        if (installed != nullptr) ::FwpmFreeMemory0(reinterpret_cast<void**>(&installed));
        if (!verified) {
            Fail(error, "wfp_filter_verify_failed", result);
            Close();
            return false;
        }
    }
    for (std::uint64_t id : created) owned_.insert(id);
    *filterIds = std::move(created);
    error->clear();
    return true;
}

bool DynamicWfpSession::Release(const std::vector<std::uint64_t>& filterIds,
                                std::string* error) {
    if (error == nullptr) return false;
    if (engine_ == nullptr) { Fail(error, "wfp_session_closed"); return false; }
    if (filterIds.empty()) { error->clear(); return true; }
    std::set<std::uint64_t> unique(filterIds.begin(), filterIds.end());
    if (unique.size() != filterIds.size()) {
        Fail(error, "wfp_duplicate_filter_id");
        return false;
    }
    for (std::uint64_t id : filterIds)
        if (owned_.find(id) == owned_.end()) {
            Fail(error, "wfp_filter_not_owned");
            return false;
        }
    DWORD result = ::FwpmTransactionBegin0(engine_, 0);
    if (result != ERROR_SUCCESS) {
        Fail(error, "wfp_transaction_failed", result);
        return false;
    }
    for (std::uint64_t id : filterIds) {
        result = ::FwpmFilterDeleteById0(engine_, id);
        if (result != ERROR_SUCCESS) break;
    }
    if (result == ERROR_SUCCESS) result = ::FwpmTransactionCommit0(engine_);
    else (void)::FwpmTransactionAbort0(engine_);
    if (result != ERROR_SUCCESS) {
        Fail(error, "wfp_filter_release_failed", result);
        // Do not leave a lease half released if WFP committed unexpectedly.
        Close();
        return false;
    }
    for (std::uint64_t id : filterIds) owned_.erase(id);
    error->clear();
    return true;
}

bool DynamicWfpBackend::Install(const RestrictionPlan& plan,
                                 std::vector<std::uint64_t>* ids,
                                 std::string* error) {
    if (!session_.Open(error)) return false;
    return session_.Apply(plan, ids, error);
}

bool DynamicWfpBackend::Remove(const std::vector<std::uint64_t>& ids,
                                std::string* error) {
    return session_.Release(ids, error);
}

}  // namespace wintcp
