// Common Pin Analyzer Tools 
// - String Related Utility
// 2015.04.25. 
// seogu.choi@gmail.com


#include "pin.H"
// #include <string>
// #include <cctype>  
// #include <sstream>
// #include <algorithm>
// #include <iomanip>

#define toHex4(val) StringHex(val, 8, false)
#define toHex8(val) hexstr(val, 8).substr(2)
#define	toHex1(val) StringHex(val, 2, false)


#ifdef TARGET_IA32
#define	toHex(val) toHex4(val)
#elif TARGET_IA32E
#define	toHex(val) toHex8(val)
#endif
