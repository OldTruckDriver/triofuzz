cmake_minimum_required(VERSION 3.16)
project(TrioFuzz VERSION 1.0.0 LANGUAGES C CXX)

# TrioFuzz: Unified Multi-Algorithm Fuzzer
# Integrates XFuzz Thompson Sampling + MOpt PSO + MuoFuzz Markov Chain

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 设置编译器选项
set(CMAKE_CXX_FLAGS_DEBUG "-g -O1 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# 可选：启用细粒度性能插装（会带来额外开销）
option(ENABLE_DETAILED_PERF "Enable detailed per-iteration perf instrumentation" OFF)
if(ENABLE_DETAILED_PERF)
    add_compile_definitions(ENABLE_DETAILED_PERF=1)
else()
    add_compile_definitions(ENABLE_DETAILED_PERF=0)
endif()

# 添加必要的编译器宏和标志来修复标准库问题
add_compile_definitions(_GNU_SOURCE)
add_compile_definitions(_GLIBCXX_USE_C99)
add_compile_definitions(_GLIBCXX_USE_C99_STDINT_TR1)

# 检测编译器类型并设置相应的覆盖率标志
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # Clang编译器：使用trace-pc-guard
    set(COVERAGE_FLAGS "-fsanitize-coverage=trace-pc-guard")
    message(STATUS "Using Clang compiler with trace-pc-guard coverage")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    # GCC编译器：使用trace-pc作为替代
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ftemplate-backtrace-limit=0")
    set(COVERAGE_FLAGS "-fsanitize-coverage=trace-pc")
    message(STATUS "Using GCC compiler with trace-pc coverage")
else()
    # 其他编译器：默认不使用覆盖率
    set(COVERAGE_FLAGS "")
    message(WARNING "Unknown compiler: ${CMAKE_CXX_COMPILER_ID}. Coverage instrumentation may not work.")
endif()

# 为用户目标代码导出覆盖率标志
set(TRIOFUZZ_COVERAGE_FLAGS "${COVERAGE_FLAGS}" CACHE STRING "Coverage flags for target compilation")

# 查找依赖包
find_package(Threads REQUIRED)

# Use local json.hpp from external/include (single-header version)
# This avoids network dependency on GitHub during build
add_library(nlohmann_json INTERFACE)
target_include_directories(nlohmann_json INTERFACE ${CMAKE_SOURCE_DIR}/external/include)
add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
message(STATUS "Using local nlohmann/json.hpp from external/include")

# 包含目录
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/external/include)

# 创建库目标
# 收集所有源文件
# 注意: src/core/*.cpp 包含:
#   - fuzzing_engine.cpp (主引擎实现)
#   - specialized_thread_engine.cpp (专职线程架构实现)
#   - engine_thread_helpers.cpp (线程安全辅助类)
#   - 其他核心组件
# 已移除: fuzzing_engine_with_unified.cpp (旧版本，已归档)
file(GLOB_RECURSE TRIOFUZZ_SOURCES
    "src/types/*.cpp"
    "src/core/*.cpp"
    "src/utils/*.cpp"
    "src/algorithms/*/*.cpp"
    "src/combination/*.cpp"
    "src/ui/*.cpp"
)

# 移除main.cpp从库源文件中
list(REMOVE_ITEM TRIOFUZZ_SOURCES "${CMAKE_SOURCE_DIR}/src/main.cpp")

# 排除TUI主程序文件（避免多个main函数冲突）
list(REMOVE_ITEM TRIOFUZZ_SOURCES "${CMAKE_SOURCE_DIR}/src/ui/tui_main.cpp")

# 所有算法现在都编译，通过 algorithm_config.hpp 控制启用/禁用
# 临时排除有接口问题的instrumentation算法
list(REMOVE_ITEM TRIOFUZZ_SOURCES "${CMAKE_SOURCE_DIR}/src/algorithms/instrumentation/cmplog_instrumentation.cpp")
list(REMOVE_ITEM TRIOFUZZ_SOURCES "${CMAKE_SOURCE_DIR}/src/algorithms/instrumentation/control_flow_instrumentation.cpp")
list(REMOVE_ITEM TRIOFUZZ_SOURCES "${CMAKE_SOURCE_DIR}/src/algorithms/instrumentation/data_flow_instrumentation.cpp")
list(REMOVE_ITEM TRIOFUZZ_SOURCES "${CMAKE_SOURCE_DIR}/src/algorithms/instrumentation/edge_coverage_instrumentation.cpp")
list(REMOVE_ITEM TRIOFUZZ_SOURCES "${CMAKE_SOURCE_DIR}/src/algorithms/instrumentation/taint_tracking.cpp")

# 添加我们的新文件
set(ADDITIONAL_SOURCES
    "${CMAKE_SOURCE_DIR}/src/core/state_manager.cpp"
    "${CMAKE_SOURCE_DIR}/src/core/engine_thread_helpers.cpp"
    "${CMAKE_SOURCE_DIR}/src/core/enhanced_crash_tracker.cpp"
    "${CMAKE_SOURCE_DIR}/src/core/algorithm_combination_manager.cpp"
    "${CMAKE_SOURCE_DIR}/src/core/enhanced_combination_executor.cpp"
    "${CMAKE_SOURCE_DIR}/src/core/thompson_sampling.cpp"
    "${CMAKE_SOURCE_DIR}/src/algorithms/optimization/pso_specialization.cpp"
    "${CMAKE_SOURCE_DIR}/src/algorithms/optimization/multi_objective_optimization.cpp"
    "${CMAKE_SOURCE_DIR}/src/utils/random_utils.cpp"
    
    # 注意：以下算法已被归档到 archive/unused_algorithms/
    # adaptive_length, angora_gradient_descent, libfuzzer_structured,
    # zest, adaptive_mutation_orchestrator, reinforcement_learning, neural_network,
    # transformer, advanced_coverage_scheduler,
    # enhanced_energy_scheduler, binary_pso, angora_strategy, icc_aggressive
    # 已恢复使用: gradient_descent, deterministic, smart_format, aflgo,
    # runtime_dictionary, value_approximation, rare_edge_scheduler, fast_scheduler, performance_analyzer
    # "${CMAKE_SOURCE_DIR}/src/algorithms/mutation/libfuzzer_mutation.cpp"
    # "${CMAKE_SOURCE_DIR}/src/algorithms/mutation/fairfuzz_mutation.cpp" # 已解耦，不再使用
    # "${CMAKE_SOURCE_DIR}/src/algorithms/mutation/zest_mutation.cpp"
    # "${CMAKE_SOURCE_DIR}/src/algorithms/mutation/neuzz_mutation.cpp" # 已归档
    # "${CMAKE_SOURCE_DIR}/src/algorithms/scheduling/mopt_scheduler.cpp" # 已归档

    # 解耦后的新算法 - rare_branch已归档
    # "${CMAKE_SOURCE_DIR}/src/algorithms/mutation/rare_branch_mutation.cpp"
    
    # 新的简洁接口文件
    "${CMAKE_SOURCE_DIR}/src/interface/triofuzz_main.cpp"
    
    # 保留的算法源文件
    "${CMAKE_SOURCE_DIR}/src/algorithms/mutation/redqueen_mutation.cpp" # 已归档 - 极慢
    # "${CMAKE_SOURCE_DIR}/src/algorithms/mutation/aflgo_mutation.cpp" # 已归档
    # "${CMAKE_SOURCE_DIR}/src/algorithms/mutation/sage_mutation.cpp"
    # "${CMAKE_SOURCE_DIR}/src/algorithms/mutation/honggfuzz_mutation.cpp" # 已归档
    # "${CMAKE_SOURCE_DIR}/src/algorithms/mutation/format_aware_mutation.cpp" # 已归档
    # "${CMAKE_SOURCE_DIR}/src/algorithms/mutation/icc_profile_mutation.cpp" # 已归档
    # "${CMAKE_SOURCE_DIR}/src/algorithms/mutation/jpeg_mutation.cpp" # 已归档

    # 恢复的算法
    "${CMAKE_SOURCE_DIR}/src/algorithms/scheduling/rare_edge_scheduler.cpp"
    # "${CMAKE_SOURCE_DIR}/src/algorithms/scheduling/fast_scheduler.cpp" # 已归档
    # "${CMAKE_SOURCE_DIR}/src/algorithms/feedback/performance_analyzer.cpp" # 已归档
    # runtime_dictionary 和 value_approximation 是 header-only 实现
)

# 创建TrioFuzz库
add_library(triofuzz_lib STATIC ${TRIOFUZZ_SOURCES} ${ADDITIONAL_SOURCES})
set_target_properties(triofuzz_lib PROPERTIES POSITION_INDEPENDENT_CODE ON)

# 创建TrioFuzz主库（包含main函数）- 用户链接这个库
add_library(triofuzz STATIC 
    ${TRIOFUZZ_SOURCES}
    "${CMAKE_SOURCE_DIR}/src/interface/triofuzz_main.cpp"
)
set_target_properties(triofuzz PROPERTIES POSITION_INDEPENDENT_CODE ON)

# 创建OBJECT库来生成.o文件
add_library(triofuzz_objects OBJECT ${TRIOFUZZ_SOURCES} ${ADDITIONAL_SOURCES})
set_target_properties(triofuzz_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)

# 为OBJECT库添加同样的编译选项和链接依赖
target_compile_definitions(triofuzz_objects PRIVATE $<TARGET_PROPERTY:triofuzz_lib,COMPILE_DEFINITIONS>)
target_include_directories(triofuzz_objects PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/external/include)

# 检查是否需要额外的数学库
find_library(MATH_LIBRARY m)
if(MATH_LIBRARY)
    set(EXTRA_LIBS ${MATH_LIBRARY})
endif()

# 查找OpenSSL库（用于增强的crash追踪器）
find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    set(EXTRA_LIBS ${EXTRA_LIBS} OpenSSL::Crypto)
    message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
else()
    message(FATAL_ERROR "OpenSSL is required for enhanced crash tracking")
endif()

# 查找libdl库（用于符号解析）
find_library(DL_LIBRARY dl)
if(DL_LIBRARY)
    set(EXTRA_LIBS ${EXTRA_LIBS} ${DL_LIBRARY})
endif()

# 查找librt库（用于共享内存操作）
find_library(RT_LIBRARY rt)
if(RT_LIBRARY)
    set(EXTRA_LIBS ${EXTRA_LIBS} ${RT_LIBRARY})
endif()

# 链接线程库和JSON库到所有库
target_link_libraries(triofuzz_lib Threads::Threads ${EXTRA_LIBS})
target_link_libraries(triofuzz Threads::Threads ${EXTRA_LIBS})

if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(triofuzz_lib nlohmann_json::nlohmann_json)
    target_link_libraries(triofuzz nlohmann_json::nlohmann_json)
    # 为OBJECT库添加JSON的include目录
    get_target_property(JSON_INCLUDE_DIRS nlohmann_json::nlohmann_json INTERFACE_INCLUDE_DIRECTORIES)
    if(JSON_INCLUDE_DIRS)
        target_include_directories(triofuzz_objects PRIVATE ${JSON_INCLUDE_DIRS})
    endif()
else()
    target_link_libraries(triofuzz_lib nlohmann_json)
    target_link_libraries(triofuzz nlohmann_json)
    # 为OBJECT库添加JSON的include目录（如果能找到的话）
    find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp)
    if(NLOHMANN_JSON_INCLUDE_DIR)
        target_include_directories(triofuzz_objects PRIVATE ${NLOHMANN_JSON_INCLUDE_DIR})
    endif()
endif()

# 创建主可执行文件（用于开发测试）
add_executable(triofuzz_test
    src/interface/triofuzz_main.cpp
    src/interface/dummy_fuzzer.cpp  # 添加虚拟fuzzer实现
)
target_link_libraries(triofuzz_test triofuzz_lib)
# 添加编译器特定的profile选项
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    # Clang编译器：使用LLVM profile runtime
    target_compile_options(triofuzz_test PRIVATE -fprofile-instr-generate)
    target_link_options(triofuzz_test PRIVATE -fprofile-instr-generate)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    # GCC编译器：使用GCC profile选项
    target_compile_options(triofuzz_test PRIVATE -fprofile-generate)
    target_link_options(triofuzz_test PRIVATE -fprofile-generate)
endif()


# 添加安全版本的宏接口测试
# add_executable(test_collaborative_macro experiment/drivers/test_collaborative_macro.cpp)
# target_link_libraries(test_collaborative_macro triofuzz_lib)

# 为test_collaborative_macro添加覆盖率插装
# if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
#     target_compile_options(test_collaborative_macro PRIVATE -fsanitize-coverage=trace-pc-guard)
#     target_link_options(test_collaborative_macro PRIVATE -fsanitize-coverage=trace-pc-guard)
# elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
#     # GCC: 使用 fuzzing_engine.cpp 中的覆盖率收集实现
#     # target_compile_options(test_collaborative_macro PRIVATE -fprofile-generate -fprofile-update=atomic)
#     # target_link_options(test_collaborative_macro PRIVATE -fprofile-generate)
# endif()


# 添加编译器特定的优化选项
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

# 为神经网络算法添加额外的编译器标志
if(CMAKE_BUILD_TYPE MATCHES Release)
    target_compile_definitions(triofuzz_lib PRIVATE ENABLE_NEURAL_OPTIMIZATIONS)
    target_compile_definitions(triofuzz_objects PRIVATE ENABLE_NEURAL_OPTIMIZATIONS)
endif()

# 安装目标
install(TARGETS triofuzz DESTINATION bin)
install(TARGETS triofuzz DESTINATION lib)
# install(TARGETS collafuzz_lib DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)

# 测试
enable_testing()

# 添加一个简单的测试
add_test(NAME basic_test COMMAND triofuzz --help)

# 添加havoc专用测试
add_test(NAME havoc_test_help COMMAND test_havoc --help)

# 添加宏接口测试
add_test(NAME simple_fuzz_target_help COMMAND simple_fuzz_target --help)
add_test(NAME collaborative_fuzz_target_help COMMAND collaborative_fuzz_target --help)
add_test(NAME angora_fuzz_target_help COMMAND angora_fuzz_target --help)
add_test(NAME advanced_cpp_target_help COMMAND advanced_cpp_target --help)

# 新增的宏接口测试用例
add_test(NAME test_macro_interface_help COMMAND test_macro_interface --help)
add_test(NAME test_collaborative_macro_help COMMAND test_collaborative_macro --help)
add_test(NAME test_angora_macro_help COMMAND test_angora_macro --help)
add_test(NAME test_custom_macro_help COMMAND test_custom_macro --help)

# 打印配置信息
message(STATUS "TrioFuzz Configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  Macro Interface: Enabled")
message(STATUS "  Examples built: simple_fuzz_target, collaborative_fuzz_target, angora_fuzz_target, advanced_cpp_target")

# 添加编译选项
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

# Debug信息
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(triofuzz_lib PRIVATE DEBUG=1)
    target_compile_definitions(triofuzz_objects PRIVATE DEBUG=1)
endif()

# 创建配置文件安装
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

# 添加最小化调试版本
# add_executable(debug_minimal examples/debug_minimal.cpp)
# target_link_libraries(debug_minimal collafuzz_lib)
