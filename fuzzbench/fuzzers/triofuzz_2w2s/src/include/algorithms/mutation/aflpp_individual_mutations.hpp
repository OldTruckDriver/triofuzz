#pragma once

/**
 * @file aflpp_individual_mutations.hpp
 * @brief 37 individual AFL++ mutation operators as separate algorithms
 *
 * Each mutation operator from AFL++ havoc stage is implemented as an independent
 * MutationAlgorithm class to enable Thompson Sampling at the operator level,
 * matching AFL++ TS Parallel for fair comparison.
 *
 * Mutation operators (37 total):
 * 00. MUT_FLIPBIT          - Flip a single random bit
 * 01. MUT_INTERESTING8     - Set 8-bit interesting value
 * 02. MUT_INTERESTING16    - Set 16-bit interesting value (LE)
 * 03. MUT_INTERESTING16BE  - Set 16-bit interesting value (BE)
 * 04. MUT_INTERESTING32    - Set 32-bit interesting value (LE)
 * 05. MUT_INTERESTING32BE  - Set 32-bit interesting value (BE)
 * 06. MUT_ARITH8_          - 8-bit subtraction
 * 07. MUT_ARITH8           - 8-bit addition
 * 08. MUT_ARITH16_         - 16-bit subtraction (LE)
 * 09. MUT_ARITH16BE_       - 16-bit subtraction (BE)
 * 10. MUT_ARITH16          - 16-bit addition (LE)
 * 11. MUT_ARITH16BE        - 16-bit addition (BE)
 * 12. MUT_ARITH32_         - 32-bit subtraction (LE)
 * 13. MUT_ARITH32BE_       - 32-bit subtraction (BE)
 * 14. MUT_ARITH32          - 32-bit addition (LE)
 * 15. MUT_ARITH32BE        - 32-bit addition (BE)
 * 16. MUT_RAND8            - Set random byte
 * 17. MUT_CLONE_COPY       - Clone bytes from input
 * 18. MUT_CLONE_FIXED      - Insert fixed bytes
 * 19. MUT_OVERWRITE_COPY   - Overwrite with bytes from input
 * 20. MUT_OVERWRITE_FIXED  - Overwrite with fixed byte
 * 21. MUT_BYTEADD          - Add 1 to byte
 * 22. MUT_BYTESUB          - Subtract 1 from byte
 * 23. MUT_FLIP8            - Flip entire byte (XOR 0xFF)
 * 24. MUT_SWITCH           - Switch two byte ranges
 * 25. MUT_DEL              - Delete bytes
 * 26. MUT_SHUFFLE          - Shuffle bytes in a range
 * 27. MUT_DELONE           - Delete single byte
 * 28. MUT_INSERTONE        - Insert single byte
 * 29. MUT_ASCIINUM         - Mutate ASCII number
 * 30. MUT_INSERTASCIINUM   - Insert ASCII number
 * 31. MUT_EXTRA_OVERWRITE  - Overwrite with dictionary token
 * 32. MUT_EXTRA_INSERT     - Insert dictionary token
 * 33. MUT_AUTO_EXTRA_OVERWRITE - Overwrite with auto dictionary
 * 34. MUT_AUTO_EXTRA_INSERT    - Insert auto dictionary token
 * 35. MUT_SPLICE_OVERWRITE - Overwrite with splice data
 * 36. MUT_SPLICE_INSERT    - Insert splice data
 */

#include "base_mutation.hpp"
#include "aflpp_mutations_common.hpp"
#include "../../core/context.hpp"
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>

namespace triofuzz {

//=============================================================================
// Base class for AFL++ individual mutations
//=============================================================================
class AFLPPBaseMutation : public MutationAlgorithm {
protected:
    mutable aflpp::AFLRandom rng_;
    size_t max_len_ = aflpp::MAX_FILE;

    // Dictionary entries (shared across dictionary-based mutations)
    std::vector<std::vector<uint8_t>> extras_;
    std::vector<std::vector<uint8_t>> auto_extras_;

public:
    AFLPPBaseMutation() = default;

    void setMaxLen(size_t max_len) { max_len_ = max_len; }
    void setExtras(const std::vector<std::vector<uint8_t>>& extras) { extras_ = extras; }
    void setAutoExtras(const std::vector<std::vector<uint8_t>>& auto_extras) { auto_extras_ = auto_extras; }
    void addAutoExtra(const std::vector<uint8_t>& extra) {
        if (auto_extras_.size() < 4096) {  // AFL++ limit
            auto_extras_.push_back(extra);
        }
    }

    void saveState(StateWriter& writer) const override {}
    void loadState(StateReader& reader) override {}
};

//=============================================================================
// 00. MUT_FLIPBIT - Flip a single random bit
//=============================================================================
class MutFlipbit : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size());
        output[pos] ^= (1 << rng_.below(8));
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_flipbit";
        info.version = "1.0";
        info.description = "AFL++ MUT_FLIPBIT - Flip a single random bit";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 01. MUT_INTERESTING8 - Set 8-bit interesting value
//=============================================================================
class MutInteresting8 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size());
        output[pos] = static_cast<uint8_t>(
            aflpp::interesting_8[rng_.below(aflpp::interesting_8_count)]);
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_interesting8";
        info.version = "1.0";
        info.description = "AFL++ MUT_INTERESTING8 - Set 8-bit interesting value";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 02. MUT_INTERESTING16 - Set 16-bit interesting value (little endian)
//=============================================================================
class MutInteresting16 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 2) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 1);
        int16_t val = aflpp::interesting_16[rng_.below(aflpp::interesting_16_count)];
        aflpp::write16(&output[pos], static_cast<uint16_t>(val));
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_interesting16";
        info.version = "1.0";
        info.description = "AFL++ MUT_INTERESTING16 - Set 16-bit interesting value (LE)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 03. MUT_INTERESTING16BE - Set 16-bit interesting value (big endian)
//=============================================================================
class MutInteresting16BE : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 2) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 1);
        int16_t val = aflpp::interesting_16[rng_.below(aflpp::interesting_16_count)];
        aflpp::write16(&output[pos], aflpp::swap16(static_cast<uint16_t>(val)));
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_interesting16be";
        info.version = "1.0";
        info.description = "AFL++ MUT_INTERESTING16BE - Set 16-bit interesting value (BE)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 04. MUT_INTERESTING32 - Set 32-bit interesting value (little endian)
//=============================================================================
class MutInteresting32 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 4) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 3);
        int32_t val = aflpp::interesting_32[rng_.below(aflpp::interesting_32_count)];
        aflpp::write32(&output[pos], static_cast<uint32_t>(val));
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_interesting32";
        info.version = "1.0";
        info.description = "AFL++ MUT_INTERESTING32 - Set 32-bit interesting value (LE)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 05. MUT_INTERESTING32BE - Set 32-bit interesting value (big endian)
//=============================================================================
class MutInteresting32BE : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 4) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 3);
        int32_t val = aflpp::interesting_32[rng_.below(aflpp::interesting_32_count)];
        aflpp::write32(&output[pos], aflpp::swap32(static_cast<uint32_t>(val)));
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_interesting32be";
        info.version = "1.0";
        info.description = "AFL++ MUT_INTERESTING32BE - Set 32-bit interesting value (BE)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 06. MUT_ARITH8_ - 8-bit subtraction
//=============================================================================
class MutArith8Sub : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size());
        uint8_t delta = 1 + rng_.below(aflpp::ARITH_MAX);
        output[pos] -= delta;
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_arith8_sub";
        info.version = "1.0";
        info.description = "AFL++ MUT_ARITH8_ - 8-bit subtraction";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 07. MUT_ARITH8 - 8-bit addition
//=============================================================================
class MutArith8Add : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size());
        uint8_t delta = 1 + rng_.below(aflpp::ARITH_MAX);
        output[pos] += delta;
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_arith8_add";
        info.version = "1.0";
        info.description = "AFL++ MUT_ARITH8 - 8-bit addition";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 08. MUT_ARITH16_ - 16-bit subtraction (little endian)
//=============================================================================
class MutArith16Sub : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 2) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 1);
        uint16_t val = aflpp::read16(&output[pos]);
        uint16_t delta = 1 + rng_.below(aflpp::ARITH_MAX);
        aflpp::write16(&output[pos], val - delta);
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_arith16_sub";
        info.version = "1.0";
        info.description = "AFL++ MUT_ARITH16_ - 16-bit subtraction (LE)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 09. MUT_ARITH16BE_ - 16-bit subtraction (big endian)
//=============================================================================
class MutArith16BESub : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 2) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 1);
        uint16_t val = aflpp::swap16(aflpp::read16(&output[pos]));
        uint16_t delta = 1 + rng_.below(aflpp::ARITH_MAX);
        aflpp::write16(&output[pos], aflpp::swap16(val - delta));
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_arith16be_sub";
        info.version = "1.0";
        info.description = "AFL++ MUT_ARITH16BE_ - 16-bit subtraction (BE)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 10. MUT_ARITH16 - 16-bit addition (little endian)
//=============================================================================
class MutArith16Add : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 2) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 1);
        uint16_t val = aflpp::read16(&output[pos]);
        uint16_t delta = 1 + rng_.below(aflpp::ARITH_MAX);
        aflpp::write16(&output[pos], val + delta);
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_arith16_add";
        info.version = "1.0";
        info.description = "AFL++ MUT_ARITH16 - 16-bit addition (LE)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 11. MUT_ARITH16BE - 16-bit addition (big endian)
//=============================================================================
class MutArith16BEAdd : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 2) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 1);
        uint16_t val = aflpp::swap16(aflpp::read16(&output[pos]));
        uint16_t delta = 1 + rng_.below(aflpp::ARITH_MAX);
        aflpp::write16(&output[pos], aflpp::swap16(val + delta));
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_arith16be_add";
        info.version = "1.0";
        info.description = "AFL++ MUT_ARITH16BE - 16-bit addition (BE)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 12. MUT_ARITH32_ - 32-bit subtraction (little endian)
//=============================================================================
class MutArith32Sub : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 4) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 3);
        uint32_t val = aflpp::read32(&output[pos]);
        uint32_t delta = 1 + rng_.below(aflpp::ARITH_MAX);
        aflpp::write32(&output[pos], val - delta);
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_arith32_sub";
        info.version = "1.0";
        info.description = "AFL++ MUT_ARITH32_ - 32-bit subtraction (LE)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 13. MUT_ARITH32BE_ - 32-bit subtraction (big endian)
//=============================================================================
class MutArith32BESub : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 4) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 3);
        uint32_t val = aflpp::swap32(aflpp::read32(&output[pos]));
        uint32_t delta = 1 + rng_.below(aflpp::ARITH_MAX);
        aflpp::write32(&output[pos], aflpp::swap32(val - delta));
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_arith32be_sub";
        info.version = "1.0";
        info.description = "AFL++ MUT_ARITH32BE_ - 32-bit subtraction (BE)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 14. MUT_ARITH32 - 32-bit addition (little endian)
//=============================================================================
class MutArith32Add : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 4) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 3);
        uint32_t val = aflpp::read32(&output[pos]);
        uint32_t delta = 1 + rng_.below(aflpp::ARITH_MAX);
        aflpp::write32(&output[pos], val + delta);
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_arith32_add";
        info.version = "1.0";
        info.description = "AFL++ MUT_ARITH32 - 32-bit addition (LE)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 15. MUT_ARITH32BE - 32-bit addition (big endian)
//=============================================================================
class MutArith32BEAdd : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 4) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 3);
        uint32_t val = aflpp::swap32(aflpp::read32(&output[pos]));
        uint32_t delta = 1 + rng_.below(aflpp::ARITH_MAX);
        aflpp::write32(&output[pos], aflpp::swap32(val + delta));
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_arith32be_add";
        info.version = "1.0";
        info.description = "AFL++ MUT_ARITH32BE - 32-bit addition (BE)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 16. MUT_RAND8 - Set random byte
//=============================================================================
class MutRand8 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size());
        output[pos] ^= 1 + rng_.below(255);
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_rand8";
        info.version = "1.0";
        info.description = "AFL++ MUT_RAND8 - Set random byte";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 17. MUT_CLONE_COPY - Clone bytes from within input
//=============================================================================
class MutCloneCopy : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty() || input.size() >= max_len_) return input;

        MutationOutput output = input;
        uint32_t clone_len = aflpp::choose_block_len(rng_, static_cast<uint32_t>(output.size()));

        if (output.size() + clone_len > max_len_) {
            clone_len = static_cast<uint32_t>(max_len_ - output.size());
        }
        if (clone_len == 0) return output;

        uint32_t clone_from = rng_.below(static_cast<uint32_t>(output.size()) - clone_len + 1);
        uint32_t clone_to = rng_.below(static_cast<uint32_t>(output.size()));

        // Insert cloned bytes
        std::vector<uint8_t> cloned(output.begin() + clone_from,
                                    output.begin() + clone_from + clone_len);
        output.insert(output.begin() + clone_to, cloned.begin(), cloned.end());

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_clone_copy";
        info.version = "1.0";
        info.description = "AFL++ MUT_CLONE_COPY - Clone bytes from input";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 18. MUT_CLONE_FIXED - Insert fixed bytes
//=============================================================================
class MutCloneFixed : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() >= max_len_) return input;

        MutationOutput output = input;
        uint32_t clone_len = aflpp::choose_block_len(rng_, static_cast<uint32_t>(aflpp::MAX_FILE));

        if (output.size() + clone_len > max_len_) {
            clone_len = static_cast<uint32_t>(max_len_ - output.size());
        }
        if (clone_len == 0) return output;

        uint32_t clone_to = rng_.below(static_cast<uint32_t>(output.size()) + 1);
        uint8_t fill_byte = rng_.below(2) ? rng_.rand8() :
                           (rng_.below(2) ? 0 : 255);

        // Insert fixed bytes
        output.insert(output.begin() + clone_to, clone_len, fill_byte);

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_clone_fixed";
        info.version = "1.0";
        info.description = "AFL++ MUT_CLONE_FIXED - Insert fixed bytes";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 19. MUT_OVERWRITE_COPY - Overwrite with bytes from input
//=============================================================================
class MutOverwriteCopy : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 2) return input;

        MutationOutput output = input;
        uint32_t copy_len = aflpp::choose_block_len(rng_, static_cast<uint32_t>(output.size()) - 1);
        uint32_t copy_from = rng_.below(static_cast<uint32_t>(output.size()) - copy_len + 1);
        uint32_t copy_to = rng_.below(static_cast<uint32_t>(output.size()) - copy_len + 1);

        if (copy_from != copy_to) {
            memmove(&output[copy_to], &output[copy_from], copy_len);
        }

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_overwrite_copy";
        info.version = "1.0";
        info.description = "AFL++ MUT_OVERWRITE_COPY - Overwrite with bytes from input";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 20. MUT_OVERWRITE_FIXED - Overwrite with fixed byte
//=============================================================================
class MutOverwriteFixed : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;

        MutationOutput output = input;
        uint32_t copy_len = aflpp::choose_block_len(rng_, static_cast<uint32_t>(output.size()));
        uint32_t copy_to = rng_.below(static_cast<uint32_t>(output.size()) - copy_len + 1);
        uint8_t fill_byte = rng_.below(2) ? rng_.rand8() :
                           (rng_.below(2) ? 0 : 255);

        memset(&output[copy_to], fill_byte, copy_len);

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_overwrite_fixed";
        info.version = "1.0";
        info.description = "AFL++ MUT_OVERWRITE_FIXED - Overwrite with fixed byte";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 21. MUT_BYTEADD - Add 1 to byte
//=============================================================================
class MutByteAdd : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size());
        output[pos]++;
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_byteadd";
        info.version = "1.0";
        info.description = "AFL++ MUT_BYTEADD - Add 1 to byte";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 22. MUT_BYTESUB - Subtract 1 from byte
//=============================================================================
class MutByteSub : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size());
        output[pos]--;
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_bytesub";
        info.version = "1.0";
        info.description = "AFL++ MUT_BYTESUB - Subtract 1 from byte";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 23. MUT_FLIP8 - Flip entire byte (XOR 0xFF)
//=============================================================================
class MutFlip8 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size());
        output[pos] ^= 0xFF;
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_flip8";
        info.version = "1.0";
        info.description = "AFL++ MUT_FLIP8 - Flip entire byte (XOR 0xFF)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 24. MUT_SWITCH - Switch two byte ranges
//=============================================================================
class MutSwitch : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 4) return input;

        MutationOutput output = input;
        uint32_t len = static_cast<uint32_t>(output.size());

        // Choose switch positions and lengths
        uint32_t switch_len = aflpp::choose_block_len(rng_, len / 4);
        uint32_t first_pos = rng_.below(len - switch_len + 1);

        uint32_t second_pos;
        uint32_t attempts = 0;
        do {
            second_pos = rng_.below(len - switch_len + 1);
            attempts++;
        } while ((second_pos >= first_pos && second_pos < first_pos + switch_len) ||
                 (first_pos >= second_pos && first_pos < second_pos + switch_len));

        if (attempts > 100) return output;

        // Swap the ranges
        std::vector<uint8_t> tmp(switch_len);
        memcpy(tmp.data(), &output[first_pos], switch_len);
        memcpy(&output[first_pos], &output[second_pos], switch_len);
        memcpy(&output[second_pos], tmp.data(), switch_len);

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_switch";
        info.version = "1.0";
        info.description = "AFL++ MUT_SWITCH - Switch two byte ranges";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 25. MUT_DEL - Delete bytes
//=============================================================================
class MutDel : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 2) return input;

        MutationOutput output = input;
        uint32_t del_len = aflpp::choose_block_len(rng_, static_cast<uint32_t>(output.size()) - 1);
        uint32_t del_from = rng_.below(static_cast<uint32_t>(output.size()) - del_len + 1);

        output.erase(output.begin() + del_from, output.begin() + del_from + del_len);

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_del";
        info.version = "1.0";
        info.description = "AFL++ MUT_DEL - Delete bytes";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 26. MUT_SHUFFLE - Shuffle bytes in a range
//=============================================================================
class MutShuffle : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 4) return input;

        MutationOutput output = input;
        uint32_t len = static_cast<uint32_t>(output.size());
        uint32_t shuffle_len = aflpp::choose_block_len(rng_, len - 1);
        uint32_t shuffle_from = rng_.below(len - shuffle_len + 1);

        // Fisher-Yates shuffle
        for (uint32_t i = shuffle_len - 1; i > 0; i--) {
            uint32_t j = rng_.below(i + 1);
            std::swap(output[shuffle_from + i], output[shuffle_from + j]);
        }

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_shuffle";
        info.version = "1.0";
        info.description = "AFL++ MUT_SHUFFLE - Shuffle bytes in a range";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 27. MUT_DELONE - Delete single byte
//=============================================================================
class MutDelOne : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 2) return input;

        MutationOutput output = input;
        size_t del_pos = rng_.below(output.size());
        output.erase(output.begin() + del_pos);

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_delone";
        info.version = "1.0";
        info.description = "AFL++ MUT_DELONE - Delete single byte";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 28. MUT_INSERTONE - Insert single byte
//=============================================================================
class MutInsertOne : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() >= max_len_) return input;

        // Fix: When input is empty, only insert random bytes to avoid accessing an empty vector.
        if (input.empty()) {
            MutationOutput output;
            output.push_back(rng_.rand8());
            return output;
        }

        MutationOutput output = input;
        size_t insert_pos = rng_.below(output.size() + 1);
        uint8_t byte = rng_.below(2) ? rng_.rand8() :
                      output[rng_.below(output.size())];

        output.insert(output.begin() + insert_pos, byte);

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_insertone";
        info.version = "1.0";
        info.description = "AFL++ MUT_INSERTONE - Insert single byte";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 29. MUT_ASCIINUM - Mutate ASCII number
//=============================================================================
class MutAsciiNum : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;

        MutationOutput output = input;

        // Find ASCII number in input
        size_t num_start = 0;
        size_t num_end = 0;
        bool found = false;

        for (size_t i = 0; i < output.size(); i++) {
            if (output[i] >= '0' && output[i] <= '9') {
                if (!found) {
                    num_start = i;
                    found = true;
                }
                num_end = i + 1;
            } else if (found) {
                break;
            }
        }

        if (!found || num_end <= num_start) {
            // No number found, just modify a random position
            size_t pos = rng_.below(output.size());
            output[pos] = '0' + rng_.below(10);
            return output;
        }

        // Parse number, mutate, and write back
        std::string num_str(output.begin() + num_start, output.begin() + num_end);
        int64_t num = 0;
        try {
            num = std::stoll(num_str);
        } catch (...) {
            num = 0;
        }

        // Mutate the number
        switch (rng_.below(6)) {
            case 0: num++; break;
            case 1: num--; break;
            case 2: num = -num; break;
            case 3: num = num * 2; break;
            case 4: num = num / 2; break;
            case 5: num = rng_.rand32() % 10000; break;
        }

        std::string new_num = std::to_string(num);

        // Replace in output
        output.erase(output.begin() + num_start, output.begin() + num_end);
        output.insert(output.begin() + num_start, new_num.begin(), new_num.end());

        // Ensure max length
        if (output.size() > max_len_) {
            output.resize(max_len_);
        }

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_asciinum";
        info.version = "1.0";
        info.description = "AFL++ MUT_ASCIINUM - Mutate ASCII number";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 30. MUT_INSERTASCIINUM - Insert ASCII number
//=============================================================================
class MutInsertAsciiNum : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() >= max_len_) return input;

        MutationOutput output = input;

        // Generate a random number string
        std::string num_str = std::to_string(rng_.rand32() % 100000);

        if (output.size() + num_str.size() > max_len_) {
            return output;
        }

        size_t insert_pos = rng_.below(output.size() + 1);
        output.insert(output.begin() + insert_pos, num_str.begin(), num_str.end());

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_insertasciinum";
        info.version = "1.0";
        info.description = "AFL++ MUT_INSERTASCIINUM - Insert ASCII number";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 31. MUT_EXTRA_OVERWRITE - Overwrite with dictionary token
//=============================================================================
class MutExtraOverwrite : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty() || extras_.empty()) return input;

        MutationOutput output = input;

        const auto& extra = extras_[rng_.below(extras_.size())];
        if (extra.empty() || extra.size() > output.size()) return output;

        size_t pos = rng_.below(output.size() - extra.size() + 1);
        memcpy(&output[pos], extra.data(), extra.size());

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_extra_overwrite";
        info.version = "1.0";
        info.description = "AFL++ MUT_EXTRA_OVERWRITE - Overwrite with dictionary token";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 32. MUT_EXTRA_INSERT - Insert dictionary token
//=============================================================================
class MutExtraInsert : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (extras_.empty()) return input;
        if (input.size() >= max_len_) return input;

        MutationOutput output = input;

        const auto& extra = extras_[rng_.below(extras_.size())];
        if (extra.empty() || output.size() + extra.size() > max_len_) return output;

        size_t pos = rng_.below(output.size() + 1);
        output.insert(output.begin() + pos, extra.begin(), extra.end());

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_extra_insert";
        info.version = "1.0";
        info.description = "AFL++ MUT_EXTRA_INSERT - Insert dictionary token";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 33. MUT_AUTO_EXTRA_OVERWRITE - Overwrite with auto dictionary
//=============================================================================
class MutAutoExtraOverwrite : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty() || auto_extras_.empty()) return input;

        MutationOutput output = input;

        const auto& extra = auto_extras_[rng_.below(auto_extras_.size())];
        if (extra.empty() || extra.size() > output.size()) return output;

        size_t pos = rng_.below(output.size() - extra.size() + 1);
        memcpy(&output[pos], extra.data(), extra.size());

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_auto_extra_overwrite";
        info.version = "1.0";
        info.description = "AFL++ MUT_AUTO_EXTRA_OVERWRITE - Overwrite with auto dictionary";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 34. MUT_AUTO_EXTRA_INSERT - Insert auto dictionary token
//=============================================================================
class MutAutoExtraInsert : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (auto_extras_.empty()) return input;
        if (input.size() >= max_len_) return input;

        MutationOutput output = input;

        const auto& extra = auto_extras_[rng_.below(auto_extras_.size())];
        if (extra.empty() || output.size() + extra.size() > max_len_) return output;

        size_t pos = rng_.below(output.size() + 1);
        output.insert(output.begin() + pos, extra.begin(), extra.end());

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_auto_extra_insert";
        info.version = "1.0";
        info.description = "AFL++ MUT_AUTO_EXTRA_INSERT - Insert auto dictionary token";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 35. MUT_SPLICE_OVERWRITE - Overwrite with splice data
//=============================================================================
class MutSpliceOverwrite : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;

        // Get splice buffer from context using safe corpus access
        std::vector<uint8_t> splice_buf;

        // Try to get another corpus entry for splicing via SharedContext
        // Use a lambda that returns bool to avoid void{} issue in template
        ctx.withCorpusDataSafe([&](const std::vector<std::vector<uint8_t>>& corpus) -> bool {
            if (!corpus.empty()) {
                // Pick a random entry different from current input
                size_t attempts = 0;
                while (attempts < 10 && splice_buf.empty()) {
                    size_t idx = rng_.below(corpus.size());
                    if (!corpus[idx].empty() && corpus[idx].size() != input.size()) {
                        splice_buf = corpus[idx];
                    }
                    attempts++;
                }
                // If no different size found, just pick any
                if (splice_buf.empty() && !corpus.empty()) {
                    splice_buf = corpus[rng_.below(corpus.size())];
                }
                return true;
            }
            return false;
        });

        if (splice_buf.empty()) return input;

        MutationOutput output = input;

        uint32_t splice_len = aflpp::choose_block_len(rng_, static_cast<uint32_t>(
            std::min(output.size(), splice_buf.size())));

        if (splice_len > splice_buf.size()) splice_len = splice_buf.size();
        if (splice_len > output.size()) splice_len = output.size();

        uint32_t splice_from = rng_.below(static_cast<uint32_t>(splice_buf.size()) - splice_len + 1);
        uint32_t splice_to = rng_.below(static_cast<uint32_t>(output.size()) - splice_len + 1);

        memcpy(&output[splice_to], &splice_buf[splice_from], splice_len);

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_splice_overwrite";
        info.version = "1.0";
        info.description = "AFL++ MUT_SPLICE_OVERWRITE - Overwrite with splice data";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// 36. MUT_SPLICE_INSERT - Insert splice data
//=============================================================================
class MutSpliceInsert : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() >= max_len_) return input;

        // Get splice buffer from context using safe corpus access
        std::vector<uint8_t> splice_buf;

        // Try to get another corpus entry for splicing via SharedContext
        // Use a lambda that returns bool to avoid void{} issue in template
        ctx.withCorpusDataSafe([&](const std::vector<std::vector<uint8_t>>& corpus) -> bool {
            if (!corpus.empty()) {
                size_t idx = rng_.below(corpus.size());
                if (!corpus[idx].empty()) {
                    splice_buf = corpus[idx];
                    return true;
                }
            }
            return false;
        });

        if (splice_buf.empty()) return input;

        MutationOutput output = input;

        uint32_t splice_len = aflpp::choose_block_len(rng_, static_cast<uint32_t>(splice_buf.size()));

        if (output.size() + splice_len > max_len_) {
            splice_len = static_cast<uint32_t>(max_len_ - output.size());
        }
        if (splice_len == 0 || splice_len > splice_buf.size()) return output;

        uint32_t splice_from = rng_.below(static_cast<uint32_t>(splice_buf.size()) - splice_len + 1);
        uint32_t splice_to = rng_.below(static_cast<uint32_t>(output.size()) + 1);

        output.insert(output.begin() + splice_to,
                     splice_buf.begin() + splice_from,
                     splice_buf.begin() + splice_from + splice_len);

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_splice_insert";
        info.version = "1.0";
        info.description = "AFL++ MUT_SPLICE_INSERT - Insert splice data";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// AFL++ MOpt (PSO) Stage Mutations (19 stages)
//
// These stages correspond to AFL++'s MOpt operator_num=19 selection space in
// afl-fuzz-one.c (MOpt havoc).
//=============================================================================

namespace aflpp_mopt_detail {
inline void flip_bit_msb(std::vector<uint8_t>& buf, uint32_t bit_idx) {
    buf[bit_idx >> 3] ^= static_cast<uint8_t>(128U >> (bit_idx & 7));
}
}  // namespace aflpp_mopt_detail

// 00. FLIP1 - Flip a single bit somewhere
class MOptFlip1 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;
        MutationOutput output = input;
        uint32_t bit = rng_.below(static_cast<uint32_t>(output.size() << 3));
        aflpp_mopt_detail::flip_bit_msb(output, bit);
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_flip1";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage FLIP1 - Flip a single bit";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 01. FLIP2 - Flip two adjacent bits
class MOptFlip2 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 2) return input;
        MutationOutput output = input;
        uint32_t bit_max = static_cast<uint32_t>(output.size() << 3);
        uint32_t start = rng_.below(bit_max - 1);
        aflpp_mopt_detail::flip_bit_msb(output, start);
        aflpp_mopt_detail::flip_bit_msb(output, start + 1);
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_flip2";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage FLIP2 - Flip two adjacent bits";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 02. FLIP4 - Flip four adjacent bits
class MOptFlip4 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 2) return input;
        MutationOutput output = input;
        uint32_t bit_max = static_cast<uint32_t>(output.size() << 3);
        uint32_t start = rng_.below(bit_max - 3);
        aflpp_mopt_detail::flip_bit_msb(output, start);
        aflpp_mopt_detail::flip_bit_msb(output, start + 1);
        aflpp_mopt_detail::flip_bit_msb(output, start + 2);
        aflpp_mopt_detail::flip_bit_msb(output, start + 3);
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_flip4";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage FLIP4 - Flip four adjacent bits";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 03. FLIP8 - Flip one byte (XOR 0xFF)
class MOptFlip8 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 4) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size());
        output[pos] ^= 0xFF;
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_flip8";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage FLIP8 - Flip a byte (XOR 0xFF)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 04. FLIP16 - Flip two bytes (XOR 0xFFFF)
class MOptFlip16 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 8) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 1);
        output[pos] ^= 0xFF;
        output[pos + 1] ^= 0xFF;
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_flip16";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage FLIP16 - Flip two bytes (XOR 0xFFFF)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 05. FLIP32 - Flip four bytes (XOR 0xFFFFFFFF)
class MOptFlip32 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 8) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 3);
        output[pos] ^= 0xFF;
        output[pos + 1] ^= 0xFF;
        output[pos + 2] ^= 0xFF;
        output[pos + 3] ^= 0xFF;
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_flip32";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage FLIP32 - Flip four bytes (XOR 0xFFFFFFFF)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 06. ARITH8 - Subtract and add on random bytes
class MOptArith8 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;
        MutationOutput output = input;
        size_t pos_sub = rng_.below(output.size());
        size_t pos_add = rng_.below(output.size());
        output[pos_sub] -= static_cast<uint8_t>(1 + rng_.below(aflpp::ARITH_MAX));
        output[pos_add] += static_cast<uint8_t>(1 + rng_.below(aflpp::ARITH_MAX));
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_arith8";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage ARITH8 - Subtract and add on random bytes";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 07. ARITH16 - Subtract and add on random 16-bit words, random endian each time
class MOptArith16 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 8) return input;
        MutationOutput output = input;

        auto do_op = [&](bool add) {
            size_t pos = rng_.below(output.size() - 1);
            uint16_t num = static_cast<uint16_t>(1 + rng_.below(aflpp::ARITH_MAX));
            uint16_t raw = aflpp::read16(&output[pos]);
            if (rng_.below(2)) {
                uint16_t v = raw;
                v = add ? static_cast<uint16_t>(v + num) : static_cast<uint16_t>(v - num);
                aflpp::write16(&output[pos], v);
            } else {
                uint16_t v_be = aflpp::swap16(raw);
                v_be = add ? static_cast<uint16_t>(v_be + num) : static_cast<uint16_t>(v_be - num);
                aflpp::write16(&output[pos], aflpp::swap16(v_be));
            }
        };

        do_op(false);
        do_op(true);
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_arith16";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage ARITH16 - Subtract and add 16-bit words with random endian";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 08. ARITH32 - Subtract and add on random 32-bit words, random endian each time
class MOptArith32 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 8) return input;
        MutationOutput output = input;

        auto do_op = [&](bool add) {
            size_t pos = rng_.below(output.size() - 3);
            uint32_t num = 1 + rng_.below(aflpp::ARITH_MAX);
            uint32_t raw = aflpp::read32(&output[pos]);
            if (rng_.below(2)) {
                uint32_t v = raw;
                v = add ? (v + num) : (v - num);
                aflpp::write32(&output[pos], v);
            } else {
                uint32_t v_be = aflpp::swap32(raw);
                v_be = add ? (v_be + num) : (v_be - num);
                aflpp::write32(&output[pos], aflpp::swap32(v_be));
            }
        };

        do_op(false);
        do_op(true);
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_arith32";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage ARITH32 - Subtract and add 32-bit words with random endian";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 09. INTEREST8 - Set byte to interesting value
class MOptInterest8 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 4) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size());
        output[pos] = static_cast<uint8_t>(aflpp::interesting_8[rng_.below(aflpp::interesting_8_count)]);
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_interest8";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage INTEREST8 - Set byte to interesting value";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 10. INTEREST16 - Set word to interesting value, randomly choosing endian
class MOptInterest16 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 8) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 1);
        int16_t val = aflpp::interesting_16[rng_.below(aflpp::interesting_16_count)];
        if (rng_.below(2)) {
            aflpp::write16(&output[pos], static_cast<uint16_t>(val));
        } else {
            aflpp::write16(&output[pos], aflpp::swap16(static_cast<uint16_t>(val)));
        }
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_interest16";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage INTEREST16 - Set word to interesting value (random endian)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 11. INTEREST32 - Set dword to interesting value, randomly choosing endian
class MOptInterest32 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 8) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size() - 3);
        int32_t val = aflpp::interesting_32[rng_.below(aflpp::interesting_32_count)];
        if (rng_.below(2)) {
            aflpp::write32(&output[pos], static_cast<uint32_t>(val));
        } else {
            aflpp::write32(&output[pos], aflpp::swap32(static_cast<uint32_t>(val)));
        }
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_interest32";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage INTEREST32 - Set dword to interesting value (random endian)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 12. RAND8 - XOR a random byte with 1..255
class MOptRand8 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;
        MutationOutput output = input;
        size_t pos = rng_.below(output.size());
        output[pos] ^= static_cast<uint8_t>(1 + rng_.below(255));
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_rand8";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage RAND8 - XOR a random byte with 1..255";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 13. DELETEBYTE - Delete a random block
class MOptDeleteByte : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 2) return input;
        MutationOutput output = input;
        uint32_t del_len = aflpp::choose_block_len(rng_, static_cast<uint32_t>(output.size()) - 1);
        uint32_t del_from = rng_.below(static_cast<uint32_t>(output.size()) - del_len + 1);
        output.erase(output.begin() + del_from, output.begin() + del_from + del_len);
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_deletebyte";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage DELETEBYTE - Delete a random block";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 14. CLONE75 - Clone bytes (75%) or insert constant bytes (25%)
class MOptClone75 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty() || input.size() >= max_len_) return input;
        if (input.size() + aflpp::HAVOC_BLK_XL >= max_len_) return input;

        MutationOutput output = input;

        bool actually_clone = rng_.below(4) != 0;  // 75%
        uint32_t clone_len = 0;
        uint32_t clone_from = 0;

        if (actually_clone) {
            clone_len = aflpp::choose_block_len(rng_, static_cast<uint32_t>(output.size()));
            clone_from = rng_.below(static_cast<uint32_t>(output.size()) - clone_len + 1);
        } else {
            clone_len = aflpp::choose_block_len(rng_, aflpp::HAVOC_BLK_XL);
        }

        if (output.size() + clone_len > max_len_) {
            clone_len = static_cast<uint32_t>(max_len_ - output.size());
        }
        if (clone_len == 0) return output;

        uint32_t clone_to = rng_.below(static_cast<uint32_t>(output.size()));

        MutationOutput new_buf;
        new_buf.reserve(output.size() + clone_len);

        new_buf.insert(new_buf.end(), output.begin(), output.begin() + clone_to);

        if (actually_clone) {
            new_buf.insert(new_buf.end(),
                           output.begin() + clone_from,
                           output.begin() + clone_from + clone_len);
        } else {
            uint8_t fill_byte = rng_.below(2) ? rng_.rand8() : output[rng_.below(output.size())];
            new_buf.insert(new_buf.end(), clone_len, fill_byte);
        }

        new_buf.insert(new_buf.end(), output.begin() + clone_to, output.end());
        return new_buf;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_clone75";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage CLONE75 - Clone bytes (75%) or insert constant bytes (25%)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 15. OVERWRITE75 - Overwrite with a copied chunk (75%) or fixed bytes (25%)
class MOptOverwrite75 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 2) return input;
        MutationOutput output = input;

        uint32_t len = static_cast<uint32_t>(output.size());
        uint32_t copy_len = aflpp::choose_block_len(rng_, len - 1);
        uint32_t copy_from = rng_.below(len - copy_len + 1);
        uint32_t copy_to = rng_.below(len - copy_len + 1);

        if (rng_.below(4) != 0) {  // 75% copy
            if (copy_from != copy_to) {
                memmove(&output[copy_to], &output[copy_from], copy_len);
            }
        } else {
            uint8_t fill_byte = rng_.below(2) ? rng_.rand8() : output[rng_.below(output.size())];
            memset(&output[copy_to], fill_byte, copy_len);
        }
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_overwrite75";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage OVERWRITE75 - Overwrite with copied chunk (75%) or fixed bytes (25%)";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 16. OVERWRITE_EXTRA - Overwrite bytes with a dictionary token (user or auto)
class MOptOverwriteExtra : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;

        const bool have_user = !extras_.empty();
        const bool have_auto = !auto_extras_.empty();
        if (!have_user && !have_auto) return input;

        const bool use_auto = (!have_user) || (have_auto && rng_.below(2));
        const auto& dict = use_auto ? auto_extras_ : extras_;
        const auto& extra = dict[rng_.below(dict.size())];
        if (extra.empty() || extra.size() > input.size()) return input;

        MutationOutput output = input;
        size_t insert_at = rng_.below(output.size() - extra.size() + 1);
        memcpy(&output[insert_at], extra.data(), extra.size());
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_overwrite_extra";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage OVERWRITE_EXTRA - Overwrite with dictionary token";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 17. INSERT_EXTRA - Insert a dictionary token (user or auto)
class MOptInsertExtra : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        const bool have_user = !extras_.empty();
        const bool have_auto = !auto_extras_.empty();
        if (!have_user && !have_auto) return input;
        if (input.size() >= max_len_) return input;

        const bool use_auto = (!have_user) || (have_auto && rng_.below(2));
        const auto& dict = use_auto ? auto_extras_ : extras_;
        const auto& extra = dict[rng_.below(dict.size())];
        if (extra.empty()) return input;

        if (input.size() + extra.size() >= max_len_) return input;

        MutationOutput output = input;
        size_t insert_at = rng_.below(output.size() + 1);
        output.insert(output.begin() + insert_at, extra.begin(), extra.end());
        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_insert_extra";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage INSERT_EXTRA - Insert dictionary token";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

// 18. SPLICE - Splice with another corpus entry (overwrite or insert)
class MOptSplice : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.empty()) return input;

        std::vector<uint8_t> splice_buf;
        ctx.withCorpusDataSafe([&](const std::vector<std::vector<uint8_t>>& corpus) -> bool {
            if (corpus.size() < 2) return false;
            for (size_t attempt = 0; attempt < 16; ++attempt) {
                const auto& candidate = corpus[rng_.below(corpus.size())];
                if (candidate.size() < 4) continue;
                if (candidate == input) continue;
                splice_buf = candidate;
                return true;
            }
            // Fallback: pick any eligible entry.
            for (const auto& candidate : corpus) {
                if (candidate.size() >= 4) {
                    splice_buf = candidate;
                    return true;
                }
            }
            return false;
        });

        if (splice_buf.empty()) return input;

        MutationOutput output = input;
        uint32_t temp_len = static_cast<uint32_t>(output.size());
        uint32_t new_len = static_cast<uint32_t>(splice_buf.size());

        const bool overwrite_mode =
            ((temp_len >= 2 && rng_.below(2)) || (temp_len + aflpp::HAVOC_BLK_XL >= max_len_));

        if (overwrite_mode) {
            uint32_t copy_len = aflpp::choose_block_len(rng_, new_len - 1);
            if (copy_len > temp_len) copy_len = temp_len;
            if (copy_len == 0) return output;
            uint32_t copy_from = rng_.below(new_len - copy_len + 1);
            uint32_t copy_to = rng_.below(temp_len - copy_len + 1);
            memmove(&output[copy_to], &splice_buf[copy_from], copy_len);
            return output;
        }

        // insert mode
        uint32_t clone_len = aflpp::choose_block_len(rng_, new_len);
        if (temp_len + clone_len > max_len_) {
            if (temp_len >= max_len_) return output;
            clone_len = static_cast<uint32_t>(max_len_ - temp_len);
        }
        if (clone_len == 0) return output;

        uint32_t clone_from = rng_.below(new_len - clone_len + 1);
        uint32_t clone_to = rng_.below(temp_len + 1);

        MutationOutput new_buf;
        new_buf.reserve(temp_len + clone_len);
        new_buf.insert(new_buf.end(), output.begin(), output.begin() + clone_to);
        new_buf.insert(new_buf.end(),
                       splice_buf.begin() + clone_from,
                       splice_buf.begin() + clone_from + clone_len);
        new_buf.insert(new_buf.end(), output.begin() + clone_to, output.end());
        return new_buf;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mopt_splice";
        info.version = "1.0";
        info.description = "AFL++ MOpt stage SPLICE - Splice with another corpus entry";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// NEW: MUT_ARITH32_LARGE - Large-step 32-bit arithmetic mutation
// For quickly reaching integer overflow boundaries
//=============================================================================
class MutArith32Large : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 4) return input;
        MutationOutput output = input;

        // Large step values for quickly reaching overflow boundaries
        static constexpr int32_t large_deltas[] = {
            256, 1024, 4096, 16384, 65536,
            0x10000, 0x100000, 0x1000000, 0x10000000,
            -256, -1024, -4096, -16384, -65536,
            -0x10000, -0x100000, -0x1000000, -0x10000000
        };
        static constexpr size_t num_deltas = sizeof(large_deltas) / sizeof(large_deltas[0]);

        size_t pos = rng_.below(output.size() - 3);
        int32_t delta = large_deltas[rng_.below(num_deltas)];

        // Try both little-endian and big-endian
        if (rng_.below(2)) {
            // Little-endian
            uint32_t val = aflpp::read32(&output[pos]);
            val = static_cast<uint32_t>(static_cast<int32_t>(val) + delta);
            aflpp::write32(&output[pos], val);
        } else {
            // Big-endian
            uint32_t val = aflpp::swap32(aflpp::read32(&output[pos]));
            val = static_cast<uint32_t>(static_cast<int32_t>(val) + delta);
            aflpp::write32(&output[pos], aflpp::swap32(val));
        }

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_arith32_large";
        info.version = "1.0";
        info.description = "Large-step 32-bit arithmetic for reaching overflow boundaries";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

//=============================================================================
// NEW: MUT_OVERFLOW32 - Integer overflow boundary value mutation
// Directly sets values known to trigger overflow when multiplied
//=============================================================================
class MutOverflow32 : public AFLPPBaseMutation {
public:
    MutationOutput execute(const MutationInput& input, SharedContext& ctx) override {
        if (input.size() < 4) return input;
        MutationOutput output = input;

        // Values that trigger overflow when multiplied by common factors
        // factor=2: 0x80000000, factor=3: 0x55555556, factor=4: 0x40000000, etc.
        static constexpr uint32_t overflow_values[] = {
            0x80000000U,  // 2^31 - overflows when *2
            0x55555556U,  // ceil(2^32/3) - overflows when *3
            0x40000000U,  // 2^30 - overflows when *4
            0x33333334U,  // ceil(2^32/5) - overflows when *5
            0x2AAAAAABU,  // ceil(2^32/6) - overflows when *6
            0x20000000U,  // 2^29 - overflows when *8
            0x10000000U,  // 2^28 - overflows when *16
            0x08000000U,  // 2^27 - overflows when *32
            0xFFFFFFFFU,  // max uint32
            0x7FFFFFFFU,  // max int32
            0x00000000U,  // zero (for underflow)
            0x00000001U,  // one
            0x0000FFFFU,  // 64K - 1
            0x00010000U,  // 64K
            0x00010001U,  // 64K + 1
            0x7FFFFF00U,  // large aligned value
            0x7FFE0000U,  // PNG max dimension range
            0x7FFF0000U,  // near max with zeroed lower
        };
        static constexpr size_t num_values = sizeof(overflow_values) / sizeof(overflow_values[0]);

        size_t pos = rng_.below(output.size() - 3);
        uint32_t val = overflow_values[rng_.below(num_values)];

        // Write in big-endian (common for image formats like PNG)
        // or little-endian based on random choice
        if (rng_.below(2)) {
            aflpp::write32(&output[pos], val);  // LE
        } else {
            aflpp::write32(&output[pos], aflpp::swap32(val));  // BE
        }

        return output;
    }

    AlgorithmInfo getInfo() const override {
        AlgorithmInfo info;
        info.name = "mut_overflow32";
        info.version = "1.0";
        info.description = "Set 32-bit integer overflow boundary values";
        info.type = AlgorithmType::Mutation;
        return info;
    }
};

} // namespace triofuzz
