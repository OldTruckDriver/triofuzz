#include "../../include/utils/relaxed_stats.hpp"

namespace triofuzz {

// Thread-local storage definitions
thread_local RelaxedStatsCollector::ThreadLocalStats RelaxedStatsCollector::local_stats_{};
thread_local size_t RelaxedStatsCollector::update_counter_ = 0;

} // namespace triofuzz
