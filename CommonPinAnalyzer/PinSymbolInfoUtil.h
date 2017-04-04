// Common Pin Analyzer Tools 
// - Symbol Info Utility
// 2015.04.25. 
// seogu.choi@gmail.com

#ifndef COMMON_PIN_ANALYZER
#define COMMON_PIN_ANALYZER


using namespace std;
#include <string>
#include "pin.H"
#include <set>
#include <map>
extern "C" {
#include "xed-interface.h"
}

// ========================================================================================================================
// executable module, section, function info by symbol information
// ========================================================================================================================


enum mod_type {
	mod_type_exe, mod_type_dll, mod_type_other
};

// function info
struct fn_info_t {
	string module_name;
	string name;
	ADDRINT saddr, eaddr;
	set<ADDRINT> obf_addrs;	// for checking obfuscated code writing
	string detailed_name();
	fn_info_t(string m, string n, ADDRINT sa, ADDRINT ea):module_name(m), name(n), saddr(sa), eaddr(ea) {};
};


// region info
struct reg_info_t {
	ADDRINT addr, size;
	reg_info_t(ADDRINT sa, ADDRINT sz):addr(sa), size(sz) {};
};

// section info
struct sec_info_t {
	string module_name;
	string name;
	ADDRINT saddr, eaddr;
	sec_info_t(string m, string n, ADDRINT sa, ADDRINT ea):module_name(m), name(n), saddr(sa), eaddr(ea) {};
};

// module info
struct mod_info_t {
	string name;
	mod_type type;
	ADDRINT saddr, eaddr;
	vector<sec_info_t*> sec_infos;
	vector<fn_info_t*> fn_infos;
	bool isDLL() {
		return (type == mod_type_dll);
	}
	bool isEXE() {
		return (type == mod_type_exe);
	}
	mod_info_t(string n, ADDRINT sa, ADDRINT ea):name(n), saddr(sa), eaddr(ea)  {
		if (n.find(".exe") != string::npos) type = mod_type_exe;
		else if (n.find(".dll") != string::npos) type = mod_type_dll;
		else type = mod_type_other;
	}
};


// output operators
std::ostream& operator<<(std::ostream &strm, const fn_info_t &a);
std::ostream& operator<<(std::ostream &strm, const reg_info_t &a);
std::ostream& operator<<(std::ostream &strm, const sec_info_t &a);
std::ostream& operator<<(std::ostream &strm, const mod_info_t &a);

// information getters
mod_info_t *GetModuleInfo(ADDRINT addr);
reg_info_t *GetRegionInfo(ADDRINT addr);
sec_info_t *GetSectionInfo(ADDRINT addr);
sec_info_t *GetNextSectionInfo(ADDRINT addr);
fn_info_t *GetFunctionInfo(ADDRINT addr);
string GetAddrInfo(ADDRINT addr);

// module info map
extern map<string, mod_info_t*> module_info_m;
extern vector<reg_info_t*> region_info_v;
extern map<ADDRINT, fn_info_t*> fn_info_m;

// XED related
#ifdef TARGET_IA32e
#define MMODE XED_MACHINE_MODE_LONG_64
#define STACK_ADDR_WIDTH XED_ADDRESS_WIDTH_64b
#else
#define MMODE XED_MACHINE_MODE_LEGACY_32
#define STACK_ADDR_WIDTH XED_ADDRESS_WIDTH_32b
#endif	// XED

#endif	// COMMON_PIN_ANALYZER