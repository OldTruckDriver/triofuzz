/**
 * @file register_aflpp_mutations.cpp
 * @brief Register all 37 individual AFL++ mutation operators
 *
 * This file registers all 37 mutation operators from AFL++ as independent
 * algorithms, enabling Thompson Sampling at the operator level for fair
 * comparison with AFL++ TS Parallel.
 */

#include "../../../include/algorithms/algorithm_registry.hpp"
#include "../../../include/algorithms/mutation/aflpp_individual_mutations.hpp"

namespace triofuzz {

void registerAFLPPIndividualMutations() {
    auto& registry = AlgorithmRegistry::getInstance();

    // Helper macro for registering mutations
    #define REGISTER_MUT(MutClass, mut_name, mut_desc) \
        { \
            AlgorithmConfig config; \
            config.name = mut_name; \
            config.category = "aflpp_mutation"; \
            config.type = AlgorithmType::Mutation; \
            config.provided_info = {InfoType::Coverage}; \
            config.required_info = {}; \
            config.description = mut_desc; \
            registry.registerAlgorithm<MutClass>(mut_name, config); \
        }

    // 00. MUT_FLIPBIT
    REGISTER_MUT(MutFlipbit, "mut_flipbit",
        "AFL++ MUT_FLIPBIT - Flip a single random bit");

    // 01. MUT_INTERESTING8
    REGISTER_MUT(MutInteresting8, "mut_interesting8",
        "AFL++ MUT_INTERESTING8 - Set 8-bit interesting value");

    // 02. MUT_INTERESTING16
    REGISTER_MUT(MutInteresting16, "mut_interesting16",
        "AFL++ MUT_INTERESTING16 - Set 16-bit interesting value (LE)");

    // 03. MUT_INTERESTING16BE
    REGISTER_MUT(MutInteresting16BE, "mut_interesting16be",
        "AFL++ MUT_INTERESTING16BE - Set 16-bit interesting value (BE)");

    // 04. MUT_INTERESTING32
    REGISTER_MUT(MutInteresting32, "mut_interesting32",
        "AFL++ MUT_INTERESTING32 - Set 32-bit interesting value (LE)");

    // 05. MUT_INTERESTING32BE
    REGISTER_MUT(MutInteresting32BE, "mut_interesting32be",
        "AFL++ MUT_INTERESTING32BE - Set 32-bit interesting value (BE)");

    // 06. MUT_ARITH8_ (subtraction)
    REGISTER_MUT(MutArith8Sub, "mut_arith8_sub",
        "AFL++ MUT_ARITH8_ - 8-bit subtraction");

    // 07. MUT_ARITH8 (addition)
    REGISTER_MUT(MutArith8Add, "mut_arith8_add",
        "AFL++ MUT_ARITH8 - 8-bit addition");

    // 08. MUT_ARITH16_ (subtraction LE)
    REGISTER_MUT(MutArith16Sub, "mut_arith16_sub",
        "AFL++ MUT_ARITH16_ - 16-bit subtraction (LE)");

    // 09. MUT_ARITH16BE_ (subtraction BE)
    REGISTER_MUT(MutArith16BESub, "mut_arith16be_sub",
        "AFL++ MUT_ARITH16BE_ - 16-bit subtraction (BE)");

    // 10. MUT_ARITH16 (addition LE)
    REGISTER_MUT(MutArith16Add, "mut_arith16_add",
        "AFL++ MUT_ARITH16 - 16-bit addition (LE)");

    // 11. MUT_ARITH16BE (addition BE)
    REGISTER_MUT(MutArith16BEAdd, "mut_arith16be_add",
        "AFL++ MUT_ARITH16BE - 16-bit addition (BE)");

    // 12. MUT_ARITH32_ (subtraction LE)
    REGISTER_MUT(MutArith32Sub, "mut_arith32_sub",
        "AFL++ MUT_ARITH32_ - 32-bit subtraction (LE)");

    // 13. MUT_ARITH32BE_ (subtraction BE)
    REGISTER_MUT(MutArith32BESub, "mut_arith32be_sub",
        "AFL++ MUT_ARITH32BE_ - 32-bit subtraction (BE)");

    // 14. MUT_ARITH32 (addition LE)
    REGISTER_MUT(MutArith32Add, "mut_arith32_add",
        "AFL++ MUT_ARITH32 - 32-bit addition (LE)");

    // 15. MUT_ARITH32BE (addition BE)
    REGISTER_MUT(MutArith32BEAdd, "mut_arith32be_add",
        "AFL++ MUT_ARITH32BE - 32-bit addition (BE)");

    // 16. MUT_RAND8
    REGISTER_MUT(MutRand8, "mut_rand8",
        "AFL++ MUT_RAND8 - Set random byte");

    // 17. MUT_CLONE_COPY
    REGISTER_MUT(MutCloneCopy, "mut_clone_copy",
        "AFL++ MUT_CLONE_COPY - Clone bytes from input");

    // 18. MUT_CLONE_FIXED
    REGISTER_MUT(MutCloneFixed, "mut_clone_fixed",
        "AFL++ MUT_CLONE_FIXED - Insert fixed bytes");

    // 19. MUT_OVERWRITE_COPY
    REGISTER_MUT(MutOverwriteCopy, "mut_overwrite_copy",
        "AFL++ MUT_OVERWRITE_COPY - Overwrite with bytes from input");

    // 20. MUT_OVERWRITE_FIXED
    REGISTER_MUT(MutOverwriteFixed, "mut_overwrite_fixed",
        "AFL++ MUT_OVERWRITE_FIXED - Overwrite with fixed byte");

    // 21. MUT_BYTEADD
    REGISTER_MUT(MutByteAdd, "mut_byteadd",
        "AFL++ MUT_BYTEADD - Add 1 to byte");

    // 22. MUT_BYTESUB
    REGISTER_MUT(MutByteSub, "mut_bytesub",
        "AFL++ MUT_BYTESUB - Subtract 1 from byte");

    // 23. MUT_FLIP8
    REGISTER_MUT(MutFlip8, "mut_flip8",
        "AFL++ MUT_FLIP8 - Flip entire byte (XOR 0xFF)");

    // 24. MUT_SWITCH
    REGISTER_MUT(MutSwitch, "mut_switch",
        "AFL++ MUT_SWITCH - Switch two byte ranges");

    // 25. MUT_DEL
    REGISTER_MUT(MutDel, "mut_del",
        "AFL++ MUT_DEL - Delete bytes");

    // 26. MUT_SHUFFLE
    REGISTER_MUT(MutShuffle, "mut_shuffle",
        "AFL++ MUT_SHUFFLE - Shuffle bytes in a range");

    // 27. MUT_DELONE
    REGISTER_MUT(MutDelOne, "mut_delone",
        "AFL++ MUT_DELONE - Delete single byte");

    // 28. MUT_INSERTONE
    REGISTER_MUT(MutInsertOne, "mut_insertone",
        "AFL++ MUT_INSERTONE - Insert single byte");

    // 29. MUT_ASCIINUM
    REGISTER_MUT(MutAsciiNum, "mut_asciinum",
        "AFL++ MUT_ASCIINUM - Mutate ASCII number");

    // 30. MUT_INSERTASCIINUM
    REGISTER_MUT(MutInsertAsciiNum, "mut_insertasciinum",
        "AFL++ MUT_INSERTASCIINUM - Insert ASCII number");

    // 31. MUT_EXTRA_OVERWRITE
    REGISTER_MUT(MutExtraOverwrite, "mut_extra_overwrite",
        "AFL++ MUT_EXTRA_OVERWRITE - Overwrite with dictionary token");

    // 32. MUT_EXTRA_INSERT
    REGISTER_MUT(MutExtraInsert, "mut_extra_insert",
        "AFL++ MUT_EXTRA_INSERT - Insert dictionary token");

    // 33. MUT_AUTO_EXTRA_OVERWRITE
    REGISTER_MUT(MutAutoExtraOverwrite, "mut_auto_extra_overwrite",
        "AFL++ MUT_AUTO_EXTRA_OVERWRITE - Overwrite with auto dictionary");

    // 34. MUT_AUTO_EXTRA_INSERT
    REGISTER_MUT(MutAutoExtraInsert, "mut_auto_extra_insert",
        "AFL++ MUT_AUTO_EXTRA_INSERT - Insert auto dictionary token");

    // 35. MUT_SPLICE_OVERWRITE
    REGISTER_MUT(MutSpliceOverwrite, "mut_splice_overwrite",
        "AFL++ MUT_SPLICE_OVERWRITE - Overwrite with splice data");

    // 36. MUT_SPLICE_INSERT
    REGISTER_MUT(MutSpliceInsert, "mut_splice_insert",
        "AFL++ MUT_SPLICE_INSERT - Insert splice data");

    // === NEW: Advanced mutation operators for bug finding ===

    // 37. MUT_ARITH32_LARGE - Large-step arithmetic for reaching overflow boundaries
    REGISTER_MUT(MutArith32Large, "mut_arith32_large",
        "Large-step 32-bit arithmetic for reaching integer overflow boundaries quickly");

    // 38. MUT_OVERFLOW32 - Direct integer overflow boundary values
    REGISTER_MUT(MutOverflow32, "mut_overflow32",
        "Set 32-bit values known to trigger integer overflow when multiplied");

    #undef REGISTER_MUT

    std::cout << "[INFO] Registered all 39 AFL++ individual mutation operators (including overflow mutations)" << std::endl;
}

} // namespace triofuzz
