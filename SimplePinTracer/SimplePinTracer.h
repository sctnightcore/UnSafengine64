// Pin Tracer
// 2015.04.25. ~
// seogu.choi@gmail.com

#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

#ifdef TARGET_IA32
constexpr auto ADDRSIZE = 4;
#else
constexpr auto ADDRSIZE = 8;
#endif

#define toHex4(val) StringHex(val, 8, false)
#define toHex8(val) hexstr(val, 8).substr(2)
#define	toHex1(val) StringHex(val, 2, false)

#define TO_ADDRINT(buf) (*static_cast<const ADDRINT*>(static_cast<const void*>(buf)))

#ifdef TARGET_IA32
#define	toHex(val) toHex4(val)
#elif TARGET_IA32E
#define	toHex(val) toHex8(val)
#endif

using namespace std;

// lock serializes access to the output file.
PIN_LOCK lock;

// standard output & file output 
ostream* fout;	// result output

map<ADDRINT, string> asmcode_m;
map<ADDRINT, string> fnname_m;
UINT8 buf[1024];	// code cache buffer size is 1KB
char cbuf[256];	// character buffer


// obfuscated module information
ADDRINT main_img_saddr = 0;	// section start address where EIP is changed into 
ADDRINT main_img_eaddr = 0;
ADDRINT main_txt_saddr = 0;	// section start address where EIP is changed into 
ADDRINT main_txt_eaddr = 0;

ADDRINT loader_saddr = 0;
ADDRINT loader_eaddr = 0;



// Instrumentation and analysis functions
void IMG_Instrument(IMG img, void* v);
void TRC_Instrument(TRACE trace, void* v);

void API_Print(CONTEXT* ctxt, ADDRINT addr, THREADID tid);
void INS_Print(CONTEXT* ctxt, ADDRINT addr, THREADID tid);

template<typename T>
constexpr auto IS_MAIN_IMG(T addr) { return (addr >= main_img_saddr && addr < main_img_eaddr); }
