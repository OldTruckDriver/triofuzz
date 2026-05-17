#include "../../../include/algorithms/mutation/base_mutation.hpp"

namespace triofuzz {

void MutationAlgorithm::saveState(StateWriter& writer) const {
    writer.writeInt("random_seed", random_gen_());
}

void MutationAlgorithm::loadState(StateReader& reader) {
    auto seed = reader.readInt("random_seed");
    if (seed.has_value()) {
        random_gen_.seed(static_cast<uint32_t>(seed.value()));
    }
}

} // namespace triofuzz 