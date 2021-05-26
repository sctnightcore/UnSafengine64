#pragma once

#include <string>
#include <map>

// log binary information
#define LOG_SECTION_INFO 1
#define LOG_IMAGE_INFO 1

// log thread information
#define LOG_THREAD 0

// log register-memory mapping for code virtualizer
#define LOG_REGISTER_MEMORY_MAPPING 0

// log call checking for API deobufscation
#define LOG_CALL_CHECK 0


#define DEBUG_PT_TRACE 0

int read_config_file(std::string config_file);
std::string get_config_str(std::string key);
bool get_config_bool(std::string key);
unsigned int get_config_dec(std::string key);
unsigned int get_config_hex(std::string key);