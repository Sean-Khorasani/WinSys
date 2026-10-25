// BoundedEventQueue.h
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <mutex>
#include <utility>

namespace wintcp {

// Bounded non-blocking producer queue used by the ETW callback. Producers
// never wait for capacity; overflow is counted and surfaced in collector
// status. The consumer waits independently and frees both count and byte caps.
template <class T>
class BoundedEventQueue {
public:
    BoundedEventQueue(std::size_t maxRecords, std::size_t maxBytes) noexcept
        : maxRecords_(maxRecords), maxBytes_(maxBytes) {}

    bool TryPush(T value, std::size_t bytes) noexcept {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (bytes > maxBytes_ || queue_.size() >= maxRecords_ ||
                bytes_ > maxBytes_ - bytes) {
                RecordDrop();
                return false;
            }
            queue_.push_back(Entry{std::move(value), bytes});
            bytes_ += bytes;
        } catch (...) {
            RecordDrop();
            return false;
        }
        ready_.notify_one();
        return true;
    }

    bool TryPop(T* value) {
        if (value == nullptr) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) return false;
        const std::size_t bytes = queue_.front().bytes;
        *value = std::move(queue_.front().value);
        queue_.pop_front();
        bytes_ = bytes <= bytes_ ? bytes_ - bytes : 0;
        return true;
    }

    template <class StopPredicate>
    void WaitForDataFor(std::chrono::milliseconds duration,
                        StopPredicate shouldStop) {
        std::unique_lock<std::mutex> lock(mutex_);
        ready_.wait_for(lock, duration, [this, &shouldStop] {
            return !queue_.empty() || shouldStop();
        });
    }

    void WakeAll() { ready_.notify_all(); }

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
        std::lock_guard<std::mutex> lock(mutex_);
        RecordDrop(static_cast<std::uint64_t>(queue_.size()));
        queue_.clear();
        bytes_ = 0;
    }

    void Reset() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.clear();
        bytes_ = 0;
        lost_ = 0;
    }

    std::uint64_t Lost() const noexcept { return lost_.load(); }
    std::size_t Size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    std::size_t Bytes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return bytes_;
    }

private:
    struct Entry {
        T value;
        std::size_t bytes = 0;
    };

    const std::size_t maxRecords_;
    const std::size_t maxBytes_;
    mutable std::mutex mutex_;
    std::condition_variable ready_;
    std::deque<Entry> queue_;
    std::size_t bytes_ = 0;
    std::atomic<std::uint64_t> lost_{0};
};

}  // namespace wintcp
