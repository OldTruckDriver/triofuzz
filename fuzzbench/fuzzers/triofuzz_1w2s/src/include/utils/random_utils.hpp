#pragma once

#include <random>
#include <memory>
#include <thread>
#include <mutex>
#include <algorithm>

namespace triofuzz {
namespace utils {

/**
 * @brief Thread-safe random utility class for CollaFuzz
 * 
 * Provides a singleton pattern for random number generation with
 * thread-local storage for high performance in multi-threaded scenarios.
 */
class RandomUtils {
public:
    using engine_type = std::mt19937_64;
    
    /**
     * @brief Get a thread-local random number generator engine
     * @return Reference to a thread-local MT19937-64 random engine
     */
    static engine_type& getEngine();
    
    /**
     * @brief Set global seed for all future engines
     * @param seed The seed value to use
     */
    static void setSeed(uint64_t seed);
    
    /**
     * @brief Generate a random integer in a range
     * @param min Minimum value (inclusive)
     * @param max Maximum value (inclusive)
     * @return Random integer in [min, max]
     */
    static int randomInt(int min, int max);
    
    /**
     * @brief Generate a random double in a range
     * @param min Minimum value (inclusive)
     * @param max Maximum value (exclusive)
     * @return Random double in [min, max)
     */
    static double randomDouble(double min = 0.0, double max = 1.0);
    
    /**
     * @brief Generate a random boolean
     * @param probability Probability of returning true (0.0 to 1.0)
     * @return Random boolean value
     */
    static bool randomBool(double probability = 0.5);
    
    /**
     * @brief Fill a buffer with random bytes
     * @param buffer Pointer to buffer to fill
     * @param size Number of bytes to generate
     */
    static void randomBytes(uint8_t* buffer, size_t size);
    
    /**
     * @brief Generate a vector of random bytes
     * @param size Number of bytes to generate
     * @return Vector containing random bytes
     */
    static std::vector<uint8_t> randomBytes(size_t size);
    
    /**
     * @brief Choose a random element from a container
     * @tparam Container Container type (must support begin(), end(), and size())
     * @param container The container to choose from
     * @return Iterator to the chosen element, or end() if container is empty
     */
    template<typename Container>
    static auto randomChoice(const Container& container) -> decltype(container.begin()) {
        if (container.empty()) {
            return container.end();
        }
        std::uniform_int_distribution<size_t> dist(0, container.size() - 1);
        auto it = container.begin();
        std::advance(it, dist(getEngine()));
        return it;
    }
    
    /**
     * @brief Shuffle a container in-place
     * @tparam Container Container type (must support begin() and end())
     * @param container The container to shuffle
     */
    template<typename Container>
    static void shuffle(Container& container) {
        std::shuffle(container.begin(), container.end(), getEngine());
    }

    /**
     * @brief Clean up thread-local storage for current thread
     * Call this before thread termination to prevent memory leaks
     */
    static void cleanupThreadLocalStorage();
    
    /**
     * @brief Register a thread for cleanup tracking
     * Internal use for automatic cleanup management
     */
    static void registerThread();
    
    /**
     * @brief Cleanup all thread-local storage
     * Should be called during application shutdown
     */
    static void cleanupAllThreads();

private:
    static std::mutex seed_mutex_;
    static uint64_t global_seed_;
    static bool seed_set_;
    
    // Thread-local engine generator
    static thread_local std::unique_ptr<engine_type> thread_engine_;
    
    // Initialize thread-local engine
    static void initializeThreadEngine();
};

} // namespace utils
} // namespace triofuzz 