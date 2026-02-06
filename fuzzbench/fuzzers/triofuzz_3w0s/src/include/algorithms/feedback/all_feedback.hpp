#pragma once

// Base class
#include "base_feedback.hpp"

// Feedback algorithms have been archived to archive/include/algorithms/feedback/
// Previously: coverage_analyzer.hpp, crash_analyzer.hpp, performance_analyzer.hpp

namespace triofuzz {

// Feedback algorithm types (archived; keep an empty tuple for build compatibility)
using AllFeedbackAlgorithms = std::tuple<>;

} // namespace triofuzz
