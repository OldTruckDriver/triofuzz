#include "../../../include/algorithms/feedback/base_feedback.hpp"

namespace triofuzz {

void FeedbackAlgorithm::saveState(StateWriter& writer) const {
    // Default state-saving implementation for feedback algorithms.
    // Subclasses can override this method to persist algorithm-specific state.
}

void FeedbackAlgorithm::loadState(StateReader& reader) {
    // Default state-loading implementation for feedback algorithms.
    // Subclasses can override this method to restore algorithm-specific state.
}

} // namespace triofuzz 
