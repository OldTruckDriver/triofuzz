#include "../../include/utils/algorithm_registry.hpp"
#include <algorithm>

namespace triofuzz {
// Only implement methods that are not already defined in the header

// Static member definitions
std::unique_ptr<AlgorithmRegistry> AlgorithmRegistry::instance_ = nullptr;
std::mutex AlgorithmRegistry::instance_mutex_;
}
