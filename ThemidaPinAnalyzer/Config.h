#pragma once
#include <iostream>

namespace Log {
    constexpr bool SECTION_INFO = false;
    constexpr bool IMAGE_INFO = false;
    constexpr bool THREAD = false;
    constexpr bool CALL_CHECK = true;
    constexpr bool IAT_SEARCH = true;
    constexpr bool MEMORY_ACCESS = true;
    constexpr bool OBFUSCATED_CALL = true;
    constexpr bool DUMP = true;
    constexpr bool TRACE = false;
    constexpr bool DEBUG = false;
};


enum class LogType {
    kLOG_SECTION_INFO,
    kLOG_IMAGE_INFO,    
    kLOG_THREAD, 
    kLOG_CALL_CHECK,
    kLOG_IAT_SEARCH,
    kLOG_MEMORY_ACCESS,
    kLOG_OBFUSCATED_CALL, 
    kLOG_DUMP, 
    kLOG_TRACE, 
    kLOG_DEBUG, 
};


std::ostream& operator<<(std::ostream& strm, const LogType& a) {
    switch (a) {
    case LogType::kLOG_SECTION_INFO   : return strm << "# SECTION_INFO: ";
    case LogType::kLOG_IMAGE_INFO: return strm << "# IMAGE_INFO: ";
    case LogType::kLOG_THREAD: return strm << "# THREAD: ";
    case LogType::kLOG_CALL_CHECK: return strm << "# CALL_CHECK: ";
    case LogType::kLOG_IAT_SEARCH: return strm << "# IAT_SEARCH: ";
    case LogType::kLOG_MEMORY_ACCESS: return strm << "# MEMORY_ACCESS: ";
    case LogType::kLOG_OBFUSCATED_CALL: return strm << "# OBFUSCATED_CALL: ";
    case LogType::kLOG_DUMP: return strm << "# DUMP: ";
    case LogType::kLOG_TRACE: return strm << "# TRACE: ";
    case LogType::kLOG_DEBUG: return strm << "# DEBUG: ";
    }  
    return strm << "UNDEFINED";
}

bool IsLogTypeEnabled(LogType lt) {
	switch (lt) {
	case LogType::kLOG_SECTION_INFO:     return Log::SECTION_INFO;
	case LogType::kLOG_IMAGE_INFO:       return Log::IMAGE_INFO;
	case LogType::kLOG_THREAD:           return Log::THREAD;
	case LogType::kLOG_CALL_CHECK:       return Log::CALL_CHECK;
	case LogType::kLOG_IAT_SEARCH:       return Log::IAT_SEARCH;
	case LogType::kLOG_MEMORY_ACCESS:    return Log::MEMORY_ACCESS;
	case LogType::kLOG_OBFUSCATED_CALL:  return Log::OBFUSCATED_CALL;
	case LogType::kLOG_DUMP:             return Log::DUMP;
	case LogType::kLOG_TRACE:            return Log::TRACE;
	case LogType::kLOG_DEBUG:            return Log::DEBUG;
	}
    return false;
}

#define DLOG(LOGTYPE, WHAT) \
    if (IsLogTypeEnabled(LOGTYPE)) {*fout << LOGTYPE << WHAT;}

