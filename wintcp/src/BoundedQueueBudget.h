// BoundedQueueBudget.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace wintcp {

// Admission/accounting for a bounded producer-consumer queue. The caller
// serializes CanAccept, Accepted, Removed, and DropPending with its queue
// mutex. Loss is atomic so status readers do not need that mutex.
class BoundedQueueBudget {
public:
    BoundedQueueBudget(std::size_t maxRecords, std::size_t maxBytes) noexcept
        : maxRecords_(maxRecords), maxBytes_(maxBytes) {}

    bool CanAccept(std::size_t bytes) const noexcept {
        return bytes <= maxBytes_ && records_ < maxRecords_ &&
               bytes_ <= maxBytes_ - bytes;
    }

    void Accepted(std::size_t bytes) noexcept {
        ++records_;
        bytes_ += bytes;
    }

    void Removed(std::size_t bytes) noexcept {
        if (records_ == 0) return;
        --records_;
        bytes_ = bytes <= bytes_ ? bytes_ - bytes : 0;
    }

    void RecordDrop(std::uint64_t count = 1) noexcept {
        std::uint64_t current = lost_.load();
        for (;;) {
            const std::uint64_t next =
                count > (std::numeric_limits<std::uint64_t>::max)() - current
                    ? (std::numeric_limits<std::uint64_t>::max)()
                    : current + count;
            if (lost_.compare_exchange_weak(current, next)) return;
        }
    }

    void DropPending() noexcept {
        RecordDrop(static_cast<std::uint64_t>(records_));
        records_ = 0;
        bytes_ = 0;
    }

    void Reset() noexcept {
        records_ = 0;
        bytes_ = 0;
        lost_ = 0;
    }

    std::uint64_t Lost() const noexcept { return lost_.load(); }
    std::size_t Records() const noexcept { return records_; }
    std::size_t Bytes() const noexcept { return bytes_; }

private:
    const std::size_t maxRecords_;
    const std::size_t maxBytes_;
    std::size_t records_ = 0;
    std::size_t bytes_ = 0;
    std::atomic<std::uint64_t> lost_{0};
};

}  // namespace wintcp
