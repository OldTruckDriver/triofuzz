#include "../../../include/algorithms/feedback/base_feedback.hpp"

namespace triofuzz {

void FeedbackAlgorithm::saveState(StateWriter& writer) const {
    // 反馈算法的默认状态保存实现
    // 子类可以重写这个方法来保存特定的状态
}

void FeedbackAlgorithm::loadState(StateReader& reader) {
    // 反馈算法的默认状态加载实现
    // 子类可以重写这个方法来加载特定的状态
}

} // namespace triofuzz 