#include "../../../include/algorithms/mutation/smart_dictionary_mutation.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <sstream>
#include <set>
#include <unordered_map>
#include <functional>

namespace triofuzz {

// 静态成员变量定义
std::unordered_map<std::string, std::vector<std::vector<uint8_t>>> SmartDictionaryMutation::dictionary_cache_;
std::mutex SmartDictionaryMutation::cache_mutex_;

MutationOutput SmartDictionaryMutation::execute(const MutationInput& input, SharedContext& ctx) {
    return measureExecution([&]() {
        // Check for dictionary files in the context
        loadDictionariesFromContext(ctx);

        // 优化：只在特定条件下提取字典，大幅减少开销
        executions_since_extract_++;
        if (executions_since_extract_ >= extract_interval_) {
            extractDictionaryFromInput(input);
            executions_since_extract_ = 0;
        }

        // 合并静态、动态和外部字典
        std::vector<std::vector<uint8_t>> combined_dict = static_dictionary_;
        combined_dict.insert(combined_dict.end(), dynamic_dictionary_.begin(), dynamic_dictionary_.end());
        combined_dict.insert(combined_dict.end(), external_dictionary_.begin(), external_dictionary_.end());

        // If the current input looks like text, avoid injecting binary tokens (especially NUL),
        // which can severely reduce parser progress for text-based targets (e.g., SQL).
        auto looks_text = [&](const MutationInput& in) {
            if (in.empty()) return false;
            size_t sample = std::min<size_t>(in.size(), 256);
            size_t printable = 0;
            size_t nul = 0;
            for (size_t i = 0; i < sample; ++i) {
                unsigned char c = static_cast<unsigned char>(in[i]);
                if (c == 0) nul++;
                if (std::isprint(c) || std::isspace(c)) printable++;
            }
            // Treat as text when mostly printable/whitespace and not dominated by NULs.
            return (printable * 100 >= sample * 85) && (nul * 10 < sample);
        };

        if (looks_text(input)) {
            std::vector<std::vector<uint8_t>> filtered;
            filtered.reserve(combined_dict.size());
            for (const auto& entry : combined_dict) {
                if (entry.empty()) continue;
                bool ok = true;
                for (uint8_t b : entry) {
                    if (b == 0) { ok = false; break; }
                    unsigned char c = static_cast<unsigned char>(b);
                    if (!(std::isprint(c) || std::isspace(c))) { ok = false; break; }
                }
                if (ok) filtered.push_back(entry);
            }
            if (!filtered.empty()) {
                combined_dict.swap(filtered);
            }
        }

        if (combined_dict.empty()) {
            return input; // 没有字典条目
        }

        // Enhanced strategy selection based on input characteristics
        std::uniform_int_distribution<int> strategy_dist(0, 5);
        int strategy = strategy_dist(random_gen_);

        // For larger dictionaries, bias towards more sophisticated strategies
        if (combined_dict.size() > 100) {
            strategy = strategy_dist(random_gen_) % 4 + 2; // Use strategies 2-5
        }

        // Select dictionary entry with better weighting
        const auto& dict_entry = selectDictionaryEntry(combined_dict, input);

        return applyDictionaryMutation(input, dict_entry, strategy);
    });
}

void SmartDictionaryMutation::loadDictionariesFromContext(SharedContext& ctx) {
    // Load dictionary file if path is set but not yet loaded
    if (!dictionary_file_path_.empty() && external_dictionary_.empty()) {
        loadDictionaryFromFile(dictionary_file_path_);
    }

    // Ingest tokens discovered by cmplog instrumentation (if any)
    // Key: "cmplog_comparisons" -> vector<pair<vector<uint8_t>, vector<uint8_t>>>
    ctx.withData<std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>>(
        "cmplog_comparisons",
        [this](const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>& pairs) {
            size_t added = 0;
            auto try_add = [this, &added](const std::vector<uint8_t>& tok) {
                if (tok.empty() || tok.size() > 32) return; // keep small, fast tokens
                if (dynamic_dictionary_set_.find(tok) != dynamic_dictionary_set_.end()) return;
                dynamic_dictionary_.push_back(tok);
                dynamic_dictionary_set_.insert(tok);
                added++;
                if (dynamic_dictionary_set_.size() > max_dynamic_entries_) {
                    // simple cap: drop oldest
                    dynamic_dictionary_set_.erase(dynamic_dictionary_.front());
                    dynamic_dictionary_.erase(dynamic_dictionary_.begin());
                }
            };

            for (const auto& pr : pairs) {
                try_add(pr.first);
                try_add(pr.second);
                if (added > 256) break; // cap per call to avoid bloat
            }
            return 0;
        });
}

std::vector<uint8_t> SmartDictionaryMutation::selectDictionaryEntry(
    const std::vector<std::vector<uint8_t>>& dictionary,
    const MutationInput& input) {

    if (dictionary.empty()) {
        return {};
    }

    // 优化：对于大字典，采样而非全量计算权重
    size_t sample_size = std::min(dictionary.size(), size_t(50));

    if (dictionary.size() <= sample_size) {
        // 小字典：完整权重计算
        std::vector<double> weights(dictionary.size(), 1.0);

        for (size_t i = 0; i < dictionary.size(); ++i) {
            const auto& entry = dictionary[i];

            // Prefer entries with interesting byte patterns
            if (hasInterestingPattern(entry)) {
                weights[i] *= 1.5;
            }

            // Prefer entries that are similar in size to the input (simplified)
            if (!input.empty()) {
                double size_ratio = static_cast<double>(entry.size()) / input.size();
                if (size_ratio > 0.5 && size_ratio < 2.0) {
                    weights[i] *= 1.5;
                }
            }
        }

        std::discrete_distribution<size_t> weighted_dist(weights.begin(), weights.end());
        return dictionary[weighted_dist(random_gen_)];
    } else {
        // 大字典：随机采样 + 简化权重
        std::uniform_int_distribution<size_t> dist(0, dictionary.size() - 1);
        std::vector<size_t> sampled_indices;
        sampled_indices.reserve(sample_size);

        for (size_t i = 0; i < sample_size; ++i) {
            sampled_indices.push_back(dist(random_gen_));
        }

        // 在采样中选择最优
        size_t best_idx = sampled_indices[0];
        double best_score = 1.0;

        for (size_t idx : sampled_indices) {
            const auto& entry = dictionary[idx];
            double score = 1.0;

            if (hasInterestingPattern(entry)) {
                score *= 1.5;
            }

            if (score > best_score) {
                best_score = score;
                best_idx = idx;
            }
        }

        return dictionary[best_idx];
    }
}

bool SmartDictionaryMutation::hasInterestingPattern(const std::vector<uint8_t>& entry) {
    if (entry.empty()) return false;
    
    // Check for null bytes, format strings, numbers, etc.
    for (uint8_t byte : entry) {
        if (byte == 0x00 || byte == 0xFF || 
            (byte >= '0' && byte <= '9') ||
            byte == '%' || byte == '\\' || byte == '"' || byte == '\'') {
            return true;
        }
    }
    
    return false;
}

bool SmartDictionaryMutation::isRelevantToInput(
    const std::vector<uint8_t>& entry,
    const MutationInput& input) {

    if (entry.empty() || input.empty()) return false;

    // 优化：只检查前4个字节，采样而非全扫描
    size_t check_len = std::min(entry.size(), size_t(4));
    size_t stride = std::max(size_t(1), input.size() / 16);  // 最多检查16个位置

    for (size_t i = 0; i + entry.size() <= input.size(); i += stride) {
        size_t matches = 0;
        for (size_t j = 0; j < check_len; ++j) {
            if (input[i + j] == entry[j]) {
                matches++;
            }
        }
        if (matches >= std::min(check_len, size_t(3))) {
            return true;
        }
    }

    return false;
}

void SmartDictionaryMutation::initializeStaticDictionary() {
    static_dictionary_ = {
        // 常见的边界值
        {0x00}, {0x01}, {0x7F}, {0x80}, {0xFF},
        {0x00, 0x00}, {0x01, 0x00}, {0xFF, 0xFF},
        {0x00, 0x00, 0x00, 0x00}, {0xFF, 0xFF, 0xFF, 0xFF},
        
        // 常见的数字
        {'0'}, {'1'}, {'9'},
        {'1', '0'}, {'1', '0', '0'}, {'2', '5', '5'},
        {'-', '1'}, {'4', '2'}, {'1', '3', '3', '7'},
        
        // 常见的分隔符
        {' '}, {'\t'}, {'\n'}, {'\r'}, {'\0'},
        {':'}, {';'}, {','}, {'.'}, {'/'}, {'\\'},
        
        // 常见的操作符
        {'+'}, {'-'}, {'*'}, {'='}, {'<'}, {'>'},
        {'&'}, {'|'}, {'^'}, {'%'}, {'!'}, {'?'},
        
        // 常见的括号
        {'('}, {')'}, {'['}, {']'}, {'{'}, {'}'},
        {'<', '/'}, {'/', '>'}, 
        
        // 常见的引号
        {'"'}, {'\''}, {'`'},
        
        // 常见的字符串
        {'h', 'e', 'l', 'l', 'o'},
        {'t', 'e', 's', 't'},
        {'a', 'd', 'm', 'i', 'n'},
        {'r', 'o', 'o', 't'},
        {'u', 's', 'e', 'r'},
        {'t', 'r', 'u', 'e'},
        {'f', 'a', 'l', 's', 'e'},
        
        // HTTP相关
        {'G', 'E', 'T'},
        {'P', 'O', 'S', 'T'},
        {'H', 'T', 'T', 'P'},
        {'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e'},
        
        // 文件格式标识
        {'%', 'P', 'D', 'F'},  // PDF
        {0x89, 'P', 'N', 'G'}, // PNG
        {0xFF, 0xD8, 0xFF},     // JPEG
        {'P', 'K'},             // ZIP
        {'I', 'I', '*', 0x00}, // TIFF little endian
        {'M', 'M', 0x00, '*'}, // TIFF big endian
        
        // Color management specific (for LCMS)
        {'I', 'C', 'C', '_', 'P', 'R', 'O', 'F', 'I', 'L', 'E'},
        {'a', 'd', 's', 'p'},  // Adobe RGB
        {'R', 'G', 'B', ' '},  // RGB color space
        {'C', 'M', 'Y', 'K'},  // CMYK
        {'G', 'R', 'A', 'Y'},  // Grayscale
        {'X', 'Y', 'Z', ' '},  // XYZ color space
        {'L', 'a', 'b', ' '},  // Lab color space
        {'s', 'R', 'G', 'B'},  // sRGB
        {'c', 'u', 'r', 'v'},  // curve tag
        {'t', 'e', 'x', 't'},  // text tag
        {'d', 'e', 's', 'c'},  // description tag
        {'c', 'p', 'r', 't'},  // copyright tag
        {'m', 'l', 'u', 'c'},  // multilingual unicode tag
        {'r', 'T', 'R', 'C'},  // red TRC
        {'g', 'T', 'R', 'C'},  // green TRC
        {'b', 'T', 'R', 'C'},  // blue TRC
        {'w', 't', 'p', 't'},  // white point
        {'r', 'X', 'Y', 'Z'},  // red colorant
        {'g', 'X', 'Y', 'Z'},  // green colorant
        {'b', 'X', 'Y', 'Z'},  // blue colorant
    };
}

std::vector<std::vector<uint8_t>> SmartDictionaryMutation::findPotentialTokens(const std::vector<uint8_t>& input) {
    std::vector<std::vector<uint8_t>> tokens;
    
    // 查找连续的可打印字符序列
    std::vector<uint8_t> current_token;
    for (uint8_t byte : input) {
        if (std::isprint(byte) && byte != ' ') {
            current_token.push_back(byte);
        } else {
            if (current_token.size() >= 2 && current_token.size() <= 16) {
                tokens.push_back(current_token);
            }
            current_token.clear();
        }
    }
    
    // 处理最后一个token
    if (current_token.size() >= 2 && current_token.size() <= 16) {
        tokens.push_back(current_token);
    }
    
    // 查找4字节标签（常见于ICC profiles）
    for (size_t i = 0; i + 3 < input.size(); ++i) {
        if (std::isalpha(input[i]) && std::isalpha(input[i+1]) && 
            std::isalpha(input[i+2]) && std::isalpha(input[i+3])) {
            std::vector<uint8_t> tag(input.begin() + i, input.begin() + i + 4);
            tokens.push_back(tag);
        }
    }
    
    // 查找重复的字节模式 - 优化版本，使用哈希表避免O(n³)复杂度
    // 不限制输入大小，保持完整的覆盖率探索能力

    for (size_t len = 2; len <= 8 && len <= input.size(); ++len) {
        std::unordered_map<std::vector<uint8_t>, size_t, VectorHash> pattern_counts;

        // 第一遍：统计所有模式的出现次数 - O(n)
        for (size_t i = 0; i <= input.size() - len; ++i) {
            std::vector<uint8_t> pattern(input.begin() + i, input.begin() + i + len);
            pattern_counts[pattern]++;
        }

        // 第二遍：添加出现多次的模式 - O(unique_patterns)
        for (const auto& pair : pattern_counts) {
            if (pair.second > 1) {
                tokens.push_back(pair.first);
            }
        }
    }
    
    return tokens;
}

MutationOutput SmartDictionaryMutation::applyDictionaryMutation(
    const MutationInput& input, 
    const std::vector<uint8_t>& dict_entry,
    int strategy) {
    
    if (dict_entry.empty()) return input;
    
    MutationOutput result = input;
    
    switch (strategy) {
        case 0: {
            // 替换策略：在输入中查找并替换现有内容
            if (result.size() >= dict_entry.size()) {
                std::uniform_int_distribution<size_t> pos_dist(0, result.size() - dict_entry.size());
                size_t pos = pos_dist(random_gen_);
                std::copy(dict_entry.begin(), dict_entry.end(), result.begin() + pos);
            }
            break;
        }
        case 1: {
            // 插入策略：在随机位置插入字典条目
            std::uniform_int_distribution<size_t> pos_dist(0, result.size());
            size_t pos = pos_dist(random_gen_);
            result.insert(result.begin() + pos, dict_entry.begin(), dict_entry.end());
            break;
        }
        case 2: {
            // 附加策略：在开头或结尾添加字典条目
            std::uniform_int_distribution<int> end_dist(0, 1);
            if (end_dist(random_gen_) == 0) {
                // 添加到开头
                result.insert(result.begin(), dict_entry.begin(), dict_entry.end());
            } else {
                // 添加到结尾
                result.insert(result.end(), dict_entry.begin(), dict_entry.end());
            }
            break;
        }
        case 3: {
            // 智能替换：查找相似的模式并替换
            if (result.size() >= dict_entry.size()) {
                size_t best_pos = 0;
                size_t best_matches = 0;
                
                for (size_t i = 0; i <= result.size() - dict_entry.size(); ++i) {
                    size_t matches = 0;
                    for (size_t j = 0; j < dict_entry.size(); ++j) {
                        if (result[i + j] == dict_entry[j]) {
                            matches++;
                        }
                    }
                    
                    if (matches > best_matches) {
                        best_matches = matches;
                        best_pos = i;
                    }
                }
                
                // 如果找到任何匹配，就替换
                if (best_matches > 0) {
                    std::copy(dict_entry.begin(), dict_entry.end(), result.begin() + best_pos);
                }
            }
            break;
        }
        case 4: {
            // 交替策略：将字典条目与现有数据交替
            MutationOutput alternated;
            size_t input_idx = 0, dict_idx = 0;
            bool use_dict = random_gen_() % 2;
            
            while (input_idx < result.size() || dict_idx < dict_entry.size()) {
                if (use_dict && dict_idx < dict_entry.size()) {
                    alternated.push_back(dict_entry[dict_idx++]);
                } else if (input_idx < result.size()) {
                    alternated.push_back(result[input_idx++]);
                }
                use_dict = !use_dict;
            }
            result = alternated;
            break;
        }
        default: {
            // 多重插入：在多个位置插入字典条目
            std::uniform_int_distribution<int> count_dist(1, 3);
            int insertions = count_dist(random_gen_);
            
            for (int i = 0; i < insertions && !result.empty(); ++i) {
                std::uniform_int_distribution<size_t> pos_dist(0, result.size());
                size_t pos = pos_dist(random_gen_);
                result.insert(result.begin() + pos, dict_entry.begin(), dict_entry.end());
            }
            break;
        }
    }
    
    return result;
}

void SmartDictionaryMutation::extractDictionaryFromInput(const std::vector<uint8_t>& input) {
    auto new_tokens = findPotentialTokens(input);

    for (const auto& token : new_tokens) {
        // 优化：使用哈希集合 O(1) 检查重复，替换 O(n) 线性搜索
        if (dynamic_dictionary_set_.find(token) == dynamic_dictionary_set_.end()) {
            dynamic_dictionary_.push_back(token);
            dynamic_dictionary_set_.insert(token);

            // 限制动态字典大小
            if (dynamic_dictionary_.size() > max_dynamic_entries_) {
                // 删除最老的条目
                const auto& oldest = dynamic_dictionary_.front();
                dynamic_dictionary_set_.erase(oldest);
                dynamic_dictionary_.erase(dynamic_dictionary_.begin());
            }
        }
    }
}

void SmartDictionaryMutation::saveState(StateWriter& writer) const {
    MutationAlgorithm::saveState(writer);
    
    // 保存动态字典
    writer.writeInt("dynamic_dict_size", dynamic_dictionary_.size());
    for (size_t i = 0; i < dynamic_dictionary_.size(); ++i) {
        const auto& entry = dynamic_dictionary_[i];
        writer.writeInt("entry_size", entry.size());
        for (size_t j = 0; j < entry.size(); ++j) {
            writer.writeInt("entry_byte", entry[j]);
        }
    }
}

void SmartDictionaryMutation::loadState(StateReader& reader) {
    MutationAlgorithm::loadState(reader);

    // 加载动态字典
    auto dict_size = reader.readInt("dynamic_dict_size");
    if (dict_size.has_value()) {
        dynamic_dictionary_.clear();
        dynamic_dictionary_set_.clear();  // 清空哈希集合

        for (size_t i = 0; i < static_cast<size_t>(dict_size.value()); ++i) {
            auto entry_size = reader.readInt("entry_size");
            if (entry_size.has_value()) {
                std::vector<uint8_t> entry;
                for (size_t j = 0; j < static_cast<size_t>(entry_size.value()); ++j) {
                    auto byte = reader.readInt("entry_byte");
                    if (byte.has_value()) {
                        entry.push_back(static_cast<uint8_t>(byte.value()));
                    }
                }
                dynamic_dictionary_.push_back(entry);
                dynamic_dictionary_set_.insert(entry);  // 同步到哈希集合
            }
        }
    }
}

bool SmartDictionaryMutation::loadDictionaryFromFile(const std::string& file_path) {
    external_dictionary_.clear();
    
    // 检查缓存
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = dictionary_cache_.find(file_path);
        if (it != dictionary_cache_.end()) {
            external_dictionary_ = it->second;
            return !external_dictionary_.empty();
        }
    }
    
    // 缓存中没有，从文件加载
    std::ifstream file(file_path);
    if (!file.is_open()) {
        std::cerr << "[SmartDictionary] Warning: Cannot open dictionary file: " << file_path << std::endl;
        return false;
    }
    
    std::string line;
    size_t line_number = 0;
    size_t loaded_entries = 0;
    
    while (std::getline(file, line)) {
        line_number++;
        
        // 跳过空行和注释
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        try {
            auto parsed_entry = parseDictionaryLine(line);
            if (!parsed_entry.empty()) {
                external_dictionary_.push_back(parsed_entry);
                loaded_entries++;
            }
        } catch (const std::exception& e) {
            std::cerr << "[SmartDictionary] Warning: Invalid dictionary entry at line " 
                      << line_number << ": " << e.what() << std::endl;
        }
    }
    
    file.close();
    
    // 加载成功后缓存结果
    if (loaded_entries > 0) {
        {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            dictionary_cache_[file_path] = external_dictionary_;
        }
        std::cout << "[SmartDictionary] Loaded " << loaded_entries 
                  << " entries from dictionary file: " << file_path << " (cached)" << std::endl;
    }
    
    return loaded_entries > 0;
}

void SmartDictionaryMutation::setDictionaryFile(const std::string& file_path) {
    dictionary_file_path_ = file_path;
    if (!file_path.empty()) {
        loadDictionaryFromFile(file_path);
    }
}

std::vector<uint8_t> SmartDictionaryMutation::parseDictionaryLine(const std::string& line) {
    std::vector<uint8_t> result;
    
    // 去除首尾空格
    std::string trimmed_line = line;
    trimmed_line.erase(0, trimmed_line.find_first_not_of(" \t"));
    trimmed_line.erase(trimmed_line.find_last_not_of(" \t") + 1);
    
    if (trimmed_line.empty()) {
        return result;
    }
    
    // 检查是否是quoted string格式 (如 "string" 或 'string')
    if ((trimmed_line.front() == '"' && trimmed_line.back() == '"') ||
        (trimmed_line.front() == '\'' && trimmed_line.back() == '\'')) {
        // 解析quoted string
        std::string content = trimmed_line.substr(1, trimmed_line.length() - 2);
        
        // 处理转义序列
        for (size_t i = 0; i < content.length(); ++i) {
            if (content[i] == '\\' && i + 1 < content.length()) {
                switch (content[i + 1]) {
                    case 'n': result.push_back('\n'); i++; break;
                    case 't': result.push_back('\t'); i++; break;
                    case 'r': result.push_back('\r'); i++; break;
                    case '\\': result.push_back('\\'); i++; break;
                    case '"': result.push_back('"'); i++; break;
                    case '\'': result.push_back('\''); i++; break;
                    case 'x': {
                        // 处理十六进制转义 \xHH
                        if (i + 3 < content.length()) {
                            std::string hex_str = content.substr(i + 2, 2);
                            try {
                                uint8_t hex_value = static_cast<uint8_t>(std::stoi(hex_str, nullptr, 16));
                                result.push_back(hex_value);
                                i += 3;
                            } catch (...) {
                                result.push_back(content[i]);
                            }
                        } else {
                            result.push_back(content[i]);
                        }
                        break;
                    }
                    default:
                        result.push_back(content[i]);
                        break;
                }
            } else {
                result.push_back(static_cast<uint8_t>(content[i]));
            }
        }
    } else if (trimmed_line.find('=') != std::string::npos) {
        // 处理 key="value" 格式
        size_t eq_pos = trimmed_line.find('=');
        if (eq_pos != std::string::npos && eq_pos + 1 < trimmed_line.length()) {
            std::string value_part = trimmed_line.substr(eq_pos + 1);
            return parseDictionaryLine(value_part);
        }
    } else {
        // 处理普通字符串（没有引号）
        for (char c : trimmed_line) {
            result.push_back(static_cast<uint8_t>(c));
        }
    }
    
    return result;
}

} // namespace triofuzz 
