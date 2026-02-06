#include "../../include/core/algorithm.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <filesystem>
#include <nlohmann/json.hpp>

namespace triofuzz {

// JSON状态写入器实现
class JsonStateWriter : public StateWriter {
private:
    nlohmann::json data_;
    
public:
    void writeInt(const std::string& key, int64_t value) override {
        data_[key] = value;
    }
    
    void writeDouble(const std::string& key, double value) override {
        data_[key] = value;
    }
    
    void writeString(const std::string& key, const std::string& value) override {
        data_[key] = value;
    }
    
    void writeBytes(const std::string& key, const std::vector<uint8_t>& data) override {
        // 将二进制数据编码为Base64
        std::string encoded;
        for (auto byte : data) {
            encoded += std::to_string(static_cast<int>(byte)) + ",";
        }
        data_[key] = encoded;
    }
    
    void writeBool(const std::string& key, bool value) override {
        data_[key] = value;
    }
    
    std::string toString() const {
        return data_.dump(2); // 格式化输出
    }
    
    void saveToFile(const std::string& filename) const {
        std::ofstream file(filename);
        if (file) {
            file << toString();
        } else {
            std::cerr << "Failed to open file for writing: " << filename << std::endl;
        }
    }
};

// JSON状态读取器实现
class JsonStateReader : public StateReader {
private:
    nlohmann::json data_;
    
public:
    // 从JSON字符串构造
    JsonStateReader(const std::string& json_str) {
        try {
            data_ = nlohmann::json::parse(json_str);
        } catch (const nlohmann::json::parse_error& e) {
            std::cerr << "JSON parse error: " << e.what() << std::endl;
        }
    }
    
    // 从JSON对象构造
    explicit JsonStateReader(const nlohmann::json& data) : data_(data) {}
    
    static JsonStateReader fromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file) {
            std::cerr << "Failed to open file for reading: " << filename << std::endl;
            return JsonStateReader(std::string("{}"));
        }
        
        std::string json_str((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
        return JsonStateReader(json_str);
    }
    
    std::optional<int64_t> readInt(const std::string& key) override {
        if (data_.contains(key) && data_[key].is_number_integer()) {
            return data_[key].get<int64_t>();
        }
        return std::nullopt;
    }
    
    std::optional<double> readDouble(const std::string& key) override {
        if (data_.contains(key) && data_[key].is_number()) {
            return data_[key].get<double>();
        }
        return std::nullopt;
    }
    
    std::optional<std::string> readString(const std::string& key) override {
        if (data_.contains(key) && data_[key].is_string()) {
            return data_[key].get<std::string>();
        }
        return std::nullopt;
    }
    
    std::optional<bool> readBool(const std::string& key) override {
        if (data_.contains(key) && data_[key].is_boolean()) {
            return data_[key].get<bool>();
        }
        return std::nullopt;
    }
    
    std::optional<std::vector<uint8_t>> readBytes(const std::string& key) override {
        if (data_.contains(key) && data_[key].is_string()) {
            try {
                std::vector<uint8_t> result;
                std::string encoded = data_[key].get<std::string>();
                std::stringstream ss(encoded);
                std::string item;
                while (std::getline(ss, item, ',')) {
                    if (!item.empty()) {
                        result.push_back(static_cast<uint8_t>(std::stoi(item)));
                    }
                }
                return result;
            } catch (const std::exception& e) {
                std::cerr << "Error decoding bytes: " << e.what() << std::endl;
            }
        }
        return std::nullopt;
    }
};

// 状态管理器实现
class StateManager {
private:
    std::string state_dir_;
    
public:
    explicit StateManager(const std::string& state_dir = "./state") 
        : state_dir_(state_dir) {}
    
    // 保存算法状态
    template<typename Input, typename Output, typename Context>
    bool saveAlgorithmState(const Algorithm<Input, Output, Context>& algorithm, const std::string& name) {
        try {
            JsonStateWriter writer;
            algorithm.saveState(writer);
            
            std::filesystem::create_directories(state_dir_);
            std::string filename = state_dir_ + "/" + name + ".json";
            writer.saveToFile(filename);
            
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Error saving algorithm state: " << e.what() << std::endl;
            return false;
        }
    }
    
    // 加载算法状态
    template<typename Input, typename Output, typename Context>
    bool loadAlgorithmState(Algorithm<Input, Output, Context>& algorithm, const std::string& name) {
        try {
            std::string filename = state_dir_ + "/" + name + ".json";
            if (!std::filesystem::exists(filename)) {
                std::cerr << "State file does not exist: " << filename << std::endl;
                return false;
            }
            
            auto reader = JsonStateReader::fromFile(filename);
            algorithm.loadState(reader);
            
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Error loading algorithm state: " << e.what() << std::endl;
            return false;
        }
    }
    
    // 保存全局状态
    bool saveGlobalState(const nlohmann::json& state, const std::string& name = "global") {
        try {
            std::filesystem::create_directories(state_dir_);
            std::string filename = state_dir_ + "/" + name + ".json";
            
            std::ofstream file(filename);
            if (!file) {
                std::cerr << "Failed to open file for writing: " << filename << std::endl;
                return false;
            }
            
            file << state.dump(2);
            return true;
        } catch (const std::exception& e) {
            std::cerr << "Error saving global state: " << e.what() << std::endl;
            return false;
        }
    }
    
    // 加载全局状态
    std::optional<nlohmann::json> loadGlobalState(const std::string& name = "global") {
        try {
            std::string filename = state_dir_ + "/" + name + ".json";
            if (!std::filesystem::exists(filename)) {
                std::cerr << "State file does not exist: " << filename << std::endl;
                return std::nullopt;
            }
            
            std::ifstream file(filename);
            if (!file) {
                std::cerr << "Failed to open file for reading: " << filename << std::endl;
                return std::nullopt;
            }
            
            nlohmann::json state;
            file >> state;
            return state;
        } catch (const std::exception& e) {
            std::cerr << "Error loading global state: " << e.what() << std::endl;
            return std::nullopt;
        }
    }
    
    // 列出所有保存的状态
    std::vector<std::string> listSavedStates() {
        std::vector<std::string> states;
        
        try {
            if (std::filesystem::exists(state_dir_)) {
                for (const auto& entry : std::filesystem::directory_iterator(state_dir_)) {
                    if (entry.is_regular_file() && entry.path().extension() == ".json") {
                        states.push_back(entry.path().stem().string());
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Error listing states: " << e.what() << std::endl;
        }
        
        return states;
    }
    
    // 删除状态
    bool deleteState(const std::string& name) {
        try {
            std::string filename = state_dir_ + "/" + name + ".json";
            return std::filesystem::remove(filename);
        } catch (const std::exception& e) {
            std::cerr << "Error deleting state: " << e.what() << std::endl;
            return false;
        }
    }
};

// 实现StateWriter的模板方法
template<typename T>
void StateWriter::write(const std::string& key, const T& value) {
    // 默认转换为字符串
    writeString(key, std::to_string(value));
}

// 实现StateReader的模板方法
template<typename T>
std::optional<T> StateReader::read(const std::string& key) {
    // 默认尝试从字符串转换
    auto str = readString(key);
    if (!str.has_value()) return std::nullopt;
    
    T value{};
    std::istringstream iss(str.value());
    if (iss >> value) {
        return value;
    }
    
    return std::nullopt;
}

} // namespace triofuzz 