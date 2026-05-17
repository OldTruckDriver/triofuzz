#pragma once

#include <atomic>
#include <array>
#include <optional>

namespace triofuzz {

template<typename T, size_t Size = 4096>
class LockFreeQueue {
private:
    struct Node {
        std::atomic<T*> data{nullptr};
        std::atomic<uint64_t> version{0};
    };

    std::array<Node, Size> buffer_;
    alignas(64) std::atomic<uint64_t> head_{0};  // Avoid false sharing
    alignas(64) std::atomic<uint64_t> tail_{0};

public:
    bool enqueue(T item) {
        uint64_t tail = tail_.load(std::memory_order_relaxed);
        uint64_t next_tail = (tail + 1) % Size;

        if (next_tail == head_.load(std::memory_order_acquire)) {
            return false; // Queue full
        }

        T* item_ptr = new T(std::move(item));
        buffer_[tail].data.store(item_ptr, std::memory_order_release);
        tail_.store(next_tail, std::memory_order_release);
        return true;
    }

    std::optional<T> dequeue() {
        uint64_t head = head_.load(std::memory_order_relaxed);

        if (head == tail_.load(std::memory_order_acquire)) {
            return std::nullopt; // Queue empty
        }

        T* item = buffer_[head].data.load(std::memory_order_acquire);
        if (item) {
            T result = std::move(*item);
            delete item;
            buffer_[head].data.store(nullptr, std::memory_order_release);
            head_.store((head + 1) % Size, std::memory_order_release);
            return result;
        }

        return std::nullopt;
    }

    bool empty() const {
        return head_.load(std::memory_order_acquire) ==
               tail_.load(std::memory_order_acquire);
    }
};

} // namespace triofuzz
