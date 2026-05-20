cmake_minimum_required(VERSION 3.16)
project(TrioFuzz VERSION 1.0.0 LANGUAGES C CXX)

# TrioFuzz: Unified Multi-Algorithm Fuzzer
# Integrates Thompson Sampling + MOpt PSO + MuoFuzz Markov Chain

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set compiler options
set(CMAKE_CXX_FLAGS_DEBUG "-g -O1 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Optional: enable fine-grained performance instrumentation (introduces extra overhead)
option(ENABLE_DETAILED_PERF "Enable detailed per-iteration perf instrumentation" OFF)
if(ENABLE_DETAILED_PERF)
    add_compile_definitions(ENABLE_DETAILED_PERF=1)
else()
    add_compile_definitions(ENABLE_DETAILED_PERF=0)
endif()

# Add necessary compiler macros and flags to fix standard library issues
add_compile_definitions(_GNU_SOURCE)
add_compile_definitions(_GLIBCXX_USE_C99)
add_compile_definitions(_GLIBCXX_USE_C99_STDINT_TR1)

# Detect compiler type and set corresponding coverage flags
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # Clang compiler: use trace-pc-guard
    set(COVERAGE_FLAGS "-fsanitize-coverage=trace-pc-guard")
    message(STATUS "Using Clang compiler with trace-pc-guard coverage")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    # GCC compiler: use trace-pc as an alternative
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ftemplate-backtrace-limit=0")
    set(COVERAGE_FLAGS "-fsanitize-coverage=trace-pc")
    message(STATUS "Using GCC compiler with trace-pc coverage")
else()
    # Other compilers: no coverage by default
    set(COVERAGE_FLAGS "")
    message(WARNING "Unknown compiler: ${CMAKE_CXX_COMPILER_ID}. Coverage instrumentation may not work.")
endif()

# Export coverage flags for user target code
set(TRIOFUZZ_COVERAGE_FLAGS "${COVERAGE_FLAGS}" CACHE STRING "Coverage flags for target compilation")

# Find dependency packages
find_package(Threads REQUIRED)

# Use local json.hpp from external/include (single-header version)
# This avoids network dependency on GitHub during build
add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json INTERFACE ${CMAKE_SOURCE_DIR}/external/include)
add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
message(STATUS "Using local nlohmann/json.hpp from external/include")

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/external/include)

# Create library target
# Collect all source files
# Note: src/core/*.cpp contains:
#   - fuzzing_engine.cpp (main engine implementation)
#   - specialized_thread_engine.cpp (dedicated thread architecture implementation)
#   - engine_thread_helpers.cpp (thread-safe helper classes)
#   - other core components
# Removed: fuzzing_engine_with_unified.cpp (legacy version, archived)
file(GLOB_RECURSE TRIOFUZZ_SOURCES
    "src/types/*.cpp"
    "src/core/*.cpp"
    "src/utils/*.cpp"
    "src/algorithms/*/*.cpp"
    "src/combination/*.cpp"
    "src/ui/*.cpp"
)

# Exclude files in the archive directory (non-default code has been moved to archive/)
list(FILTER TRIOFUZZ_SOURCES EXCLUDE REGEX ".*/archive/.*")

# Remove main.cpp from the library source files
list(REMOVE_ITEM TRIOFUZZ_SOURCES "${CMAKE_SOURCE_DIR}/src/main.cpp")

# Exclude the TUI main program file (to avoid multiple main function conflicts)
list(REMOVE_ITEM TRIOFUZZ_SOURCES "${CMAKE_SOURCE_DIR}/src/ui/tui_main.cpp")

# Additional source files (not in the GLOB paths, or need to be added explicitly)
set(ADDITIONAL_SOURCES
    "${CMAKE_SOURCE_DIR}/src/core/state_manager.cpp"
    "${CMAKE_SOURCE_DIR}/src/core/engine_thread_helpers.cpp"
    "${CMAKE_SOURCE_DIR}/src/core/enhanced_crash_tracker.cpp"
    "${CMAKE_SOURCE_DIR}/src/core/algorithm_combination_manager.cpp"
    "${CMAKE_SOURCE_DIR}/src/core/enhanced_combination_executor.cpp"
    "${CMAKE_SOURCE_DIR}/src/core/thompson_sampling.cpp"
    "${CMAKE_SOURCE_DIR}/src/algorithms/optimization/pso_specialization.cpp"
    "${CMAKE_SOURCE_DIR}/src/utils/random_utils.cpp"

    # Interface files
    "${CMAKE_SOURCE_DIR}/src/interface/triofuzz_main.cpp"

    # Retained algorithm source files
    "${CMAKE_SOURCE_DIR}/src/algorithms/mutation/redqueen_mutation.cpp"
    "${CMAKE_SOURCE_DIR}/src/algorithms/scheduling/rare_edge_scheduler.cpp"
)

# Create the TrioFuzz library
add_library(triofuzz_lib STATIC ${TRIOFUZZ_SOURCES} ${ADDITIONAL_SOURCES})
set_target_properties(triofuzz_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Create the main TrioFuzz library (includes the main function) - users link against this library
add_library(triofuzz STATIC
    ${TRIOFUZZ_SOURCES}
    "${CMAKE_SOURCE_DIR}/src/interface/triofuzz_main.cpp"
)
set_target_properties(triofuzz PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Create an OBJECT library to produce .o files
add_library(triofuzz_objects OBJECT ${TRIOFUZZ_SOURCES} ${ADDITIONAL_SOURCES})
set_target_properties(triofuzz_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Apply the same compile options and link dependencies to the OBJECT library
target_compile_definitions(triofuzz_objects PRIVATE $<TARGET_PROPERTY:triofuzz_lib,COMPILE_DEFINITIONS>)
target_include_directories(triofuzz_objects PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external/include)

# Check whether an extra math library is needed
find_library(MATH_LIBRARY m)
if(MATH_LIBRARY)
    set(EXTRA_LIBS ${MATH_LIBRARY})
endif()

# Find OpenSSL (used by the enhanced crash tracker)
find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    set(EXTRA_LIBS ${EXTRA_LIBS} OpenSSL::Crypto)
    message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
else()
    message(FATAL_ERROR "OpenSSL is required for enhanced crash tracking")
endif()

# Find libdl (used for symbol resolution)
find_library(DL_LIBRARY dl)
if(DL_LIBRARY)
    set(EXTRA_LIBS ${EXTRA_LIBS} ${DL_LIBRARY})
endif()

# Find librt (used for shared memory operations)
find_library(RT_LIBRARY rt)
if(RT_LIBRARY)
    set(EXTRA_LIBS ${EXTRA_LIBS} ${RT_LIBRARY})
endif()

# Link the threading library and JSON library to all libraries
target_link_libraries(triofuzz_lib Threads::Threads ${EXTRA_LIBS})
target_link_libraries(triofuzz Threads::Threads ${EXTRA_LIBS})

if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(triofuzz_lib nlohmann_json::nlohmann_json)
    target_link_libraries(triofuzz nlohmann_json::nlohmann_json)
    # Add JSON include directories to the OBJECT library
    get_target_property(JSON_INCLUDE_DIRS nlohmann_json::nlohmann_json INTERFACE_INCLUDE_DIRECTORIES)
    if(JSON_INCLUDE_DIRS)
        target_include_directories(triofuzz_objects PRIVATE ${JSON_INCLUDE_DIRS})
    endif()
else()
    target_link_libraries(triofuzz_lib nlohmann_json)
    target_link_libraries(triofuzz nlohmann_json)
    # Add JSON include directories to the OBJECT library (if available)
    find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp)
    if(NLOHMANN_JSON_INCLUDE_DIR)
        target_include_directories(triofuzz_objects PRIVATE ${NLOHMANN_JSON_INCLUDE_DIR})
    endif()
endif()

# Create the main executable (for development and testing)
add_executable(triofuzz_test
    src/interface/triofuzz_main.cpp
    src/interface/dummy_fuzzer.cpp  # Add the dummy fuzzer implementation
)
target_link_libraries(triofuzz_test triofuzz_lib)
# Add compiler-specific profile options
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # Clang compiler: use the LLVM profile runtime
    target_compile_options(triofuzz_test PRIVATE -fprofile-instr-generate)
    target_link_options(triofuzz_test PRIVATE -fprofile-instr-generate)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    # GCC compiler: use GCC profile options
    target_compile_options(triofuzz_test PRIVATE -fprofile-generate)
    target_link_options(triofuzz_test PRIVATE -fprofile-generate)
endif()


# Add safe-version macro interface test
# add_executable(test_collaborative_macro experiment/drivers/test_collaborative_macro.cpp)
# target_link_libraries(test_collaborative_macro triofuzz_lib)

# Add coverage instrumentation for test_collaborative_macro
# if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
#     target_compile_options(test_collaborative_macro PRIVATE -fsanitize-coverage=trace-pc-guard)
#     target_link_options(test_collaborative_macro PRIVATE -fsanitize-coverage=trace-pc-guard)
# elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
#     # GCC: rely on the coverage collection implementation in fuzzing_engine.cpp
#     # target_compile_options(test_collaborative_macro PRIVATE -fprofile-generate -fprofile-update=atomic)
#     # target_link_options(test_collaborative_macro PRIVATE -fprofile-generate)
# endif()


# Add compiler-specific optimization options
# Note: -march=native is not supported on ARM Clang, use portable optimization instead
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # Check if -march=native is supported (not on ARM Clang)
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-march=native" COMPILER_SUPPORTS_MARCH_NATIVE)

    if(COMPILER_SUPPORTS_MARCH_NATIVE)
        target_compile_options(triofuzz_lib PRIVATE -O3 -march=native)
        target_compile_options(triofuzz PRIVATE -O3 -march=native)
        target_compile_options(triofuzz_objects PRIVATE -O3 -march=native)
    else()
        # Fallback for ARM or other architectures that don't support -march=native
        target_compile_options(triofuzz_lib PRIVATE -O3)
        target_compile_options(triofuzz PRIVATE -O3)
        target_compile_options(triofuzz_objects PRIVATE -O3)
    endif()
endif()

# Add extra compiler flags for neural-network algorithms
if(CMAKE_BUILD_TYPE MATCHES Release)
    target_compile_definitions(triofuzz_lib PRIVATE ENABLE_NEURAL_OPTIMIZATIONS)
    target_compile_definitions(triofuzz_objects PRIVATE ENABLE_NEURAL_OPTIMIZATIONS)
endif()

# Install targets
install(TARGETS triofuzz DESTINATION bin)
install(TARGETS triofuzz DESTINATION lib)
# install(TARGETS collafuzz_lib DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

# Tests
enable_testing()

# Add a simple test
add_test(NAME basic_test COMMAND triofuzz --help)

# Add a havoc-specific test
add_test(NAME havoc_test_help COMMAND test_havoc --help)

# Add macro-interface tests
add_test(NAME simple_fuzz_target_help COMMAND simple_fuzz_target --help)
add_test(NAME collaborative_fuzz_target_help COMMAND collaborative_fuzz_target --help)
add_test(NAME angora_fuzz_target_help COMMAND angora_fuzz_target --help)
add_test(NAME advanced_cpp_target_help COMMAND advanced_cpp_target --help)

# New macro-interface test cases
add_test(NAME test_macro_interface_help COMMAND test_macro_interface --help)
add_test(NAME test_collaborative_macro_help COMMAND test_collaborative_macro --help)
add_test(NAME test_angora_macro_help COMMAND test_angora_macro --help)
add_test(NAME test_custom_macro_help COMMAND test_custom_macro --help)

# Print configuration information
message(STATUS "TrioFuzz Configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  Macro Interface: Enabled")
message(STATUS "  Examples built: simple_fuzz_target, collaborative_fuzz_target, angora_fuzz_target, advanced_cpp_target")

# Add compile options
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(triofuzz_lib PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wno-unused-parameter
    )
    target_compile_options(triofuzz_objects PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wno-unused-parameter
    )
endif()

# Debug information
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(triofuzz_lib PRIVATE DEBUG=1)
    target_compile_definitions(triofuzz_objects PRIVATE DEBUG=1)
endif()

# Create the config file install
file(WRITE ${CMAKE_BINARY_DIR}/default_config.json
"{\n"
"  \"execution\": {\n"
"    \"thread_count\": 4,\n"
"    \"memory_limit_mb\": 1024,\n"
"    \"timeout_ms\": 1000,\n"
"    \"max_input_size\": 1048576\n"
"  },\n"
"  \"corpus\": {\n"
"    \"max_corpus_size\": 1000000,\n"
"    \"corpus_dir\": \"./corpus\",\n"
"    \"crash_dir\": \"./crashes\"\n"
"  },\n"
"  \"monitoring\": {\n"
"    \"enable_performance_monitoring\": true,\n"
"    \"stats_interval_sec\": 60\n"
"  },\n"
"  \"output\": {\n"
"    \"output_dir\": \"./output\",\n"
"    \"log_level\": \"info\"\n"
"  }\n"
"}\n"
)

install(FILES ${CMAKE_BINARY_DIR}/default_config.json DESTINATION etc RENAME config.json)

# Add a minimal debug build
# add_executable(debug_minimal examples/debug_minimal.cpp)
# target_link_libraries(debug_minimal collafuzz_lib)
