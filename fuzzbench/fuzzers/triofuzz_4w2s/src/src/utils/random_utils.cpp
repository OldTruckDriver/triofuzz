#include "utils/random_utils.hpp"
#include <chrono>
#include <algorithm>
#include <set>
#include <atomic>
#include <thread>
#include <mutex>

namespace triofuzz {
namespace utils {

// Static member definitions
std::mutex RandomUtils::seed_mutex_;
uint64_t RandomUtils::global_seed_ = 0;
bool RandomUtils::seed_set_ = false;
thread_local std::unique_ptr<RandomUtils::engine_type> RandomUtils::thread_engine_;

// Thread tracking for cleanup
static std::mutex thread_registry_mutex_;
static std::set<std::thread::id> registered_threads_;
static std::atomic<bool> cleanup_initiated_{false};

RandomUtils::engine_type& RandomUtils::getEngine() {
    if (!thread_engine_) {
        initializeThreadEngine();
        // Register this thread for cleanup tracking
        registerThread();
    }
    return *thread_engine_;
}

void RandomUtils::setSeed(uint64_t seed) {
    std::lock_guard<std::mutex> lock(seed_mutex_);
    global_seed_ = seed;
    seed_set_ = true;
    
    // Reset thread-local engine so it gets re-initialized with new seed
    thread_engine_.reset();
}

void RandomUtils::initializeThreadEngine() {
    uint64_t seed;
    
    {
        std::lock_guard<std::mutex> lock(seed_mutex_);
        if (seed_set_) {
            // Use global seed combined with thread ID for uniqueness
            auto thread_id = std::hash<std::thread::id>{}(std::this_thread::get_id());
            seed = global_seed_ ^ thread_id;
        } else {
            // Use high-resolution clock for random seed
            auto now = std::chrono::high_resolution_clock::now();
            auto thread_id = std::hash<std::thread::id>{}(std::this_thread::get_id());
            seed = static_cast<uint64_t>(now.time_since_epoch().count()) ^ thread_id;
        }
    }
    
    thread_engine_ = std::make_unique<engine_type>(seed);
}

void RandomUtils::cleanupThreadLocalStorage() {
    // Explicitly reset the thread-local engine to release memory
    thread_engine_.reset();
    
    // Remove this thread from the registry
    {
        std::lock_guard<std::mutex> lock(thread_registry_mutex_);
        registered_threads_.erase(std::this_thread::get_id());
    }
}

void RandomUtils::registerThread() {
    if (cleanup_initiated_.load()) {
        return; // Don't register new threads during shutdown
    }
    
    std::lock_guard<std::mutex> lock(thread_registry_mutex_);
    registered_threads_.insert(std::this_thread::get_id());
}

void RandomUtils::cleanupAllThreads() {
    cleanup_initiated_.store(true);
    
    // Force cleanup of current thread's local storage
    thread_engine_.reset();
    
    std::lock_guard<std::mutex> lock(thread_registry_mutex_);
    registered_threads_.clear();
}

int RandomUtils::randomInt(int min, int max) {
    std::uniform_int_distribution<int> dist(min, max);
    return dist(getEngine());
}

double RandomUtils::randomDouble(double min, double max) {
    std::uniform_real_distribution<double> dist(min, max);
    return dist(getEngine());
}

bool RandomUtils::randomBool(double probability) {
    std::bernoulli_distribution dist(probability);
    return dist(getEngine());
}

void RandomUtils::randomBytes(uint8_t* buffer, size_t size) {
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    auto& engine = getEngine();
    
    for (size_t i = 0; i < size; ++i) {
        buffer[i] = dist(engine);
    }
}

std::vector<uint8_t> RandomUtils::randomBytes(size_t size) {
    std::vector<uint8_t> result(size);
    randomBytes(result.data(), size);
    return result;
}

} // namespace utils
} // namespace triofuzz 