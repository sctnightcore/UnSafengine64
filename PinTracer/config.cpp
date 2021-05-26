#include "config.h"
#include <string>
#include <sstream>
#include <fstream>

std::map<std::string, std::string> config;

int read_config_file(std::string config_file) {
    std::ifstream fs(config_file.c_str());
    
    if (!fs.is_open()) return 0;
    std::string line;
    while (std::getline(fs, line))
    {
        std::istringstream is_line(line);
        std::string key;
        if (std::getline(is_line, key, '='))
        {
            std::string value;
            if (std::getline(is_line, value)) {
                config[key] = value;
            }
        }
    }
    return 1;
}
    
std::string get_config_str(std::string key) {
    if (config.find(key) != config.end()) {
        return config[key];
    }
    return "";
}

bool get_config_bool(std::string key) {
    if (config.find(key) != config.end()) {
        return config[key].compare("1") == 0;
    }
    return false;
}

unsigned int get_config_dec(std::string key) {
    if (config.find(key) != config.end()) {
        int res;
        std::string val = config[key];        
        std::istringstream(val) >> res;
        return res;
    }
    return 0;
}

unsigned int get_config_hex(std::string key) {
    if (config.find(key) != config.end()) {
        int res;
        std::stringstream ss;
        ss << std::hex << config[key];
        ss >> res;
        return res;
    }
    return 0;
}
