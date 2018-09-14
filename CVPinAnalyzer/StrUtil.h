// Common Pin Analyzer Tools 
// - String Related Utility
// 2015.04.25. 
// seogu.choi@gmail.com


#include "pin.H"
#include <algorithm>
#include <string>
#include <iomanip>
#include <cctype>  
#include <sstream>

//std::string toHex(ADDRINT addr);
//std::string toHex1(ADDRINT val);
// ADDRINT fromHex(std::string str);

#define TO_LOWER(str) transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { return std::tolower(c); })

#ifdef TARGET_IA32
#define	toHex(val) StringHex(val, 8, false)
#elif TARGET_IA32E
#define	toHex(val) hexstr(val, 16).substr(2)
#endif

#define	toHex1(val) StringHex(val, 2, false)
