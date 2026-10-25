// EventDecoder.cpp
// SPDX-License-Identifier: Apache-2.0
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include "EventDecoder.h"
#include "EtwTrafficTypes.h"
#include <tdh.h>
#include <cstring>
#include <climits>
#include <string_view>
#include <utility>

namespace wintcp {
namespace {
struct TdhApi {
    using InformationFn = decltype(&::TdhGetEventInformation);
    using SizeFn = decltype(&::TdhGetPropertySize);
    using PropertyFn = decltype(&::TdhGetProperty);
    // Optional Windows component: load only on first event decode, from the
    // system directory. The process owns this module until exit.
    HMODULE module = ::LoadLibraryExW(L"tdh.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    InformationFn information = module
        ? reinterpret_cast<InformationFn>(::GetProcAddress(module, "TdhGetEventInformation")) : nullptr;
    SizeFn size = module
        ? reinterpret_cast<SizeFn>(::GetProcAddress(module, "TdhGetPropertySize")) : nullptr;
    PropertyFn property = module
        ? reinterpret_cast<PropertyFn>(::GetProcAddress(module, "TdhGetProperty")) : nullptr;
};

class TdhReader final : public EventPropertyReader {
public:
    TdhReader(EVENT_RECORD* record, TdhApi* api, TRACE_EVENT_INFO* schema,
              std::size_t schemaBytes)
        : record_(record), api_(api), schema_(schema), schemaBytes_(schemaBytes) {}
    bool Read(const wchar_t* name, std::vector<unsigned char>* bytes) override {
        PROPERTY_DATA_DESCRIPTOR descriptor = {};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
        descriptor.ArrayIndex = ULONG_MAX;
        ULONG size = 0;
        if (api_->size(record_, 0, nullptr, 1, &descriptor, &size) != ERROR_SUCCESS ||
            size == 0 || size > 4096) return false;
        bytes->resize(size);
        return api_->property(record_, 0, nullptr, 1, &descriptor, size,
                              bytes->data()) == ERROR_SUCCESS;
    }
    bool ReadText(const wchar_t* name, std::vector<unsigned char>* bytes,
                  bool* unicode) override {
        if (name == nullptr || bytes == nullptr || unicode == nullptr || schema_ == nullptr)
            return false;
        const EVENT_PROPERTY_INFO* match = nullptr;
        const ULONG count = schema_->PropertyCount;
        for (ULONG i = 0; i < count; ++i) {
            const auto& candidate = schema_->EventPropertyInfoArray[i];
            if (candidate.Flags & PropertyStruct) continue;
            const auto offset = static_cast<std::size_t>(candidate.NameOffset);
            if (offset >= schemaBytes_ || (schemaBytes_ - offset) < sizeof(wchar_t)) continue;
            const auto* propertyName = reinterpret_cast<const wchar_t*>(
                reinterpret_cast<const unsigned char*>(schema_) + offset);
            const auto chars = (schemaBytes_ - offset) / sizeof(wchar_t);
            std::size_t length = 0;
            while (length < chars && propertyName[length] != L'\0') ++length;
            if (length < chars && std::wstring_view(propertyName, length) == name) {
                match = &candidate;
                break;
            }
        }
        if (match == nullptr) return false;
        const auto inputType = match->nonStructType.InType;
        if (inputType != TDH_INTYPE_UNICODESTRING && inputType != TDH_INTYPE_ANSISTRING)
            return false;
        PROPERTY_DATA_DESCRIPTOR descriptor = {};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(name);
        descriptor.ArrayIndex = ULONG_MAX;
        ULONG size = 0;
        if (api_->size(record_, 0, nullptr, 1, &descriptor, &size) != ERROR_SUCCESS ||
            size < 2 || size > 4096) return false;
        bytes->resize(size);
        if (api_->property(record_, 0, nullptr, 1, &descriptor, size,
                           bytes->data()) != ERROR_SUCCESS) return false;
        *unicode = inputType == TDH_INTYPE_UNICODESTRING;
        return true;
    }
private:
    EVENT_RECORD* record_;
    TdhApi* api_;
    TRACE_EVENT_INFO* schema_;
    std::size_t schemaBytes_;
};

bool Read32(EventPropertyReader& reader, const wchar_t* name, std::uint32_t* out) {
    std::vector<unsigned char> bytes;
    if (!reader.Read(name, &bytes) || bytes.size() != sizeof(*out)) return false;
    std::memcpy(out, bytes.data(), sizeof(*out));
    return true;
}

bool ReadImageName(EventPropertyReader& reader, std::string* out) {
    std::vector<unsigned char> bytes;
    bool unicode = false;
    if (!reader.ReadText(L"ImageFileName", &bytes, &unicode)) return true;
    std::wstring wide;
    if (unicode) {
        if ((bytes.size() % sizeof(wchar_t)) != 0) return false;
        const auto* text = reinterpret_cast<const wchar_t*>(bytes.data());
        const auto count = bytes.size() / sizeof(wchar_t);
        std::size_t length = 0;
        while (length < count && text[length] != L'\0') ++length;
        if (length == 0 || length == count || length > 2048) return false;
        wide.assign(text, length);
    } else {
        const auto* text = reinterpret_cast<const char*>(bytes.data());
        const auto length = std::find(bytes.begin(), bytes.end(), 0) - bytes.begin();
        if (length == 0 || static_cast<std::size_t>(length) == bytes.size() || length > 4096)
            return false;
        const int needed = ::MultiByteToWideChar(CP_ACP, 0, text,
            static_cast<int>(length), nullptr, 0);
        if (needed <= 0 || needed > 2048) return false;
        wide.resize(static_cast<std::size_t>(needed));
        if (::MultiByteToWideChar(CP_ACP, 0, text, static_cast<int>(length),
                                  &wide[0], needed) != needed) return false;
        std::vector<char> roundTrip(static_cast<std::size_t>(length) + 1);
        const int restored = ::WideCharToMultiByte(CP_ACP, 0, wide.data(), needed,
            roundTrip.data(), static_cast<int>(roundTrip.size()), nullptr, nullptr);
        if (restored != length || std::memcmp(roundTrip.data(), text,
                                               static_cast<std::size_t>(length)) != 0)
            return false;
    }
    const auto length = wide.size();
    const int needed = ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.c_str(),
        static_cast<int>(length), nullptr, 0, nullptr, nullptr);
    if (needed <= 0 || needed > 4096) return false;
    out->resize(static_cast<std::size_t>(needed));
    return ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide.c_str(),
        static_cast<int>(length), &(*out)[0], needed, nullptr, nullptr) == needed;
}

bool ReadEndpoint(EventPropertyReader& reader, const wchar_t* address,
                   const wchar_t* port, bool ipv6, NetworkEndpoint* endpoint) {
    std::vector<unsigned char> ip, number;
    if (!reader.Read(address, &ip) || ip.size() != (ipv6 ? 16U : 4U) ||
        !reader.Read(port, &number) || number.size() != 2) return false;
    char text[INET6_ADDRSTRLEN] = {};
    if (::InetNtopA(ipv6 ? AF_INET6 : AF_INET, ip.data(), text, sizeof(text)) == nullptr)
        return false;
    std::uint16_t networkPort = 0;
    std::memcpy(&networkPort, number.data(), 2);
    endpoint->address = text;
    endpoint->port = ::ntohs(networkPort);
    endpoint->known = true;
    return true;
}
}  // namespace

LifecycleType ClassifyLifecycleEvent(const EVENT_HEADER& header) {
    const auto& descriptor = header.EventDescriptor;
    const USHORT architecture = header.Flags &
        (EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER);
    if (descriptor.Id != 0 || !(header.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER) ||
        (architecture != EVENT_HEADER_FLAG_32_BIT_HEADER &&
         architecture != EVENT_HEADER_FLAG_64_BIT_HEADER)) return LifecycleType::Unsupported;
    const auto opcode = descriptor.Opcode;
    if (::IsEqualGUID(header.ProviderId, kTcpIpProviderGuid) && descriptor.Version <= 2) {
        if (opcode == 12 || opcode == 28) return LifecycleType::TcpConnect;
        if (opcode == 15 || opcode == 31) return LifecycleType::TcpAccept;
        if (opcode == 13 || opcode == 29) return LifecycleType::TcpDisconnect;
    } else if (::IsEqualGUID(header.ProviderId, kUdpIpProviderGuid) && descriptor.Version <= 2) {
        if (opcode == 10 || opcode == 26) return LifecycleType::UdpSend;
        if (opcode == 11 || opcode == 27) return LifecycleType::UdpReceive;
    } else if (::IsEqualGUID(header.ProviderId, kProcessEventProviderGuid) && descriptor.Version <= 4) {
        if (opcode == 1) return LifecycleType::ProcessStart;
        if (opcode == 2) return LifecycleType::ProcessExit;
        if (opcode == 3 || opcode == 4) return LifecycleType::ProcessRundown;
    }
    return LifecycleType::Unsupported;
}

EventDecodeResult DecodeLifecycleFields(const EVENT_HEADER& header,
    EventPropertyReader& properties, DecodedLifecycleRecord* result, std::string* error) {
    if (result == nullptr || error == nullptr) return EventDecodeResult::Malformed;
    *result = {};
    error->clear();
    const auto type = ClassifyLifecycleEvent(header);
    if (type == LifecycleType::Unsupported) {
        *error = "unsupported_event_descriptor";
        return EventDecodeResult::Unsupported;
    }
    DecodedLifecycleRecord decoded;
    decoded.type = type;
    const bool process = type == LifecycleType::ProcessStart || type == LifecycleType::ProcessExit ||
        type == LifecycleType::ProcessRundown;
    if (!Read32(properties, process ? L"ProcessId" : L"PID", &decoded.pid) || decoded.pid == 0) {
        *error = "payload_pid_missing_or_invalid";
        return EventDecodeResult::Malformed;
    }
    if (!process) {
        const bool ipv6 = header.EventDescriptor.Opcode >= 26;
        decoded.family = ipv6 ? "ipv6" : "ipv4";
        // These remain source/destination observations. Local/remote roles are
        // a separate, provenance-preserving normalization step.
        if (!ReadEndpoint(properties, L"saddr", L"sport", ipv6, &decoded.source) ||
            !ReadEndpoint(properties, L"daddr", L"dport", ipv6, &decoded.destination)) {
            *error = "endpoint_schema_missing_or_invalid";
            return EventDecodeResult::Malformed;
        }
        decoded.bytesKnown = Read32(properties, L"size", &decoded.bytes);
    } else if (type == LifecycleType::ProcessStart) {
        if (!ReadImageName(properties, &decoded.observedImageName)) {
            *error = "process_image_path_invalid";
            return EventDecodeResult::Malformed;
        }
    }
    std::vector<unsigned char> key;
    if (properties.Read(process ? L"UniqueProcessKey" : L"connid", &key)) {
        const std::size_t pointerBytes = header.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER ? 8 : 4;
        if (key.size() != pointerBytes) {
            *error = "correlation_key_architecture_mismatch";
            return EventDecodeResult::Malformed;
        }
        std::memcpy(&decoded.correlationKey, key.data(), key.size());
        decoded.correlationKeyKnown = true;
    }
    *result = std::move(decoded);
    return EventDecodeResult::Decoded;
}

EventDecodeResult DecodeLifecycleRecord(const EVENT_RECORD* record,
    DecodedLifecycleRecord* result, std::string* error) {
    if (result == nullptr || error == nullptr) return EventDecodeResult::Malformed;
    *result = {};
    error->clear();
    if (record == nullptr || record->UserData == nullptr || record->UserDataLength == 0) {
        *error = "empty_event_record";
        return EventDecodeResult::Malformed;
    }
    if (ClassifyLifecycleEvent(record->EventHeader) == LifecycleType::Unsupported) {
        *error = "unsupported_event_descriptor";
        return EventDecodeResult::Unsupported;
    }
    static TdhApi api;
    if (api.information == nullptr || api.size == nullptr || api.property == nullptr) {
        *error = "tdh_unavailable";
        return EventDecodeResult::SchemaUnavailable;
    }
    EVENT_RECORD view = *record;
    ULONG bytes = 0;
    if (api.information(&view, 0, nullptr, nullptr, &bytes) != ERROR_INSUFFICIENT_BUFFER ||
        bytes < sizeof(TRACE_EVENT_INFO) || bytes > 65536) {
        *error = "event_schema_unavailable";
        return EventDecodeResult::SchemaUnavailable;
    }
    std::vector<unsigned char> schema(bytes);
    if (api.information(&view, 0, nullptr,
        reinterpret_cast<TRACE_EVENT_INFO*>(schema.data()), &bytes) != ERROR_SUCCESS) {
        *error = "event_schema_unavailable";
        return EventDecodeResult::SchemaUnavailable;
    }
    TdhReader reader(&view, &api, reinterpret_cast<TRACE_EVENT_INFO*>(schema.data()), schema.size());
    return DecodeLifecycleFields(view.EventHeader, reader, result, error);
}
}  // namespace wintcp
