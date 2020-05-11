// Common Pin Analyzer Tools 
// - Symbol Info Utility
// 2015.04.25. 
// seogu.choi@gmail.com

#ifndef COMMON_PIN_ANALYZER
#define COMMON_PIN_ANALYZER

#ifdef TARGET_IA32
constexpr auto ADDRSIZE = 4;
#else
constexpr auto ADDRSIZE = 8;
#endif

#define TO_LOWER(str) transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { return std::tolower(c); })

using namespace std;
#include <string>
#include "pin.H"
#include <set>
#include <map>
extern "C" {
#include "xed-interface.h"
}

#define TO_ADDRINT(buf) (*static_cast<const ADDRINT*>(static_cast<const void*>(buf)))
#define TO_UINT32(buf) (*static_cast<const UINT32*>(static_cast<const void*>(buf)))
#define ADDRINT_TO_BYTES(val, buf) copy(static_cast<const UINT8*>(static_cast<const void*>(&val)), static_cast<const UINT8*>(static_cast<const void*>(&val)) + ADDRSIZE, buf)

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
	bool operator==(const fn_info_t &) const;
	bool operator!=(const fn_info_t &) const;
};


// region info
struct reg_info_t {
	ADDRINT addr, size;
	reg_info_t(ADDRINT sa, ADDRINT sz):addr(sa), size(sz) {};
	bool operator==(const reg_info_t &) const;
	bool operator!=(const reg_info_t &) const;
};

// section info
struct sec_info_t {
	string module_name;
	string name;
	ADDRINT saddr, eaddr;
	sec_info_t(string m, string n, ADDRINT sa, ADDRINT ea):module_name(m), name(n), saddr(sa), eaddr(ea) {};
	bool operator==(const sec_info_t &) const;
	bool operator!=(const sec_info_t &) const;
};

// module info
struct mod_info_t {
	string name;
	string path;
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
	mod_info_t(string p, ADDRINT sa, ADDRINT ea):path(p), saddr(sa), eaddr(ea)  {
		size_t pos = p.rfind("\\") + 1;
		name = p.substr(pos);
		TO_LOWER(name);
		if (name.find(".exe") != string::npos) type = mod_type_exe;
		else if (name.find(".dll") != string::npos) type = mod_type_dll;
		else type = mod_type_other;
	}
	bool operator==(const mod_info_t &) const;
	bool operator!=(const mod_info_t &) const;
};

// output operators
std::ostream& operator<<(std::ostream &strm, const fn_info_t &a);
std::ostream& operator<<(std::ostream &strm, const sec_info_t &a);
std::ostream& operator<<(std::ostream &strm, const mod_info_t &a);

// information getters
mod_info_t *GetModuleInfo(ADDRINT addr);
reg_info_t *GetRegionInfo(ADDRINT addr);
sec_info_t *GetSectionInfo(ADDRINT addr);
sec_info_t *GetNextSectionInfo(ADDRINT addr);
fn_info_t *GetFunctionInfo(ADDRINT addr);
fn_info_t *GetFunctionInfo(string mod_name, string fn_name);
string GetAddrInfo(ADDRINT addr);

// module information
extern map<string, mod_info_t*> module_info_m;
extern vector<reg_info_t*> region_info_v;
extern map<ADDRINT, fn_info_t*> fn_info_m;
extern map<pair<string, string>, fn_info_t*> fn_str_2_fn_info;

// XED related
#ifdef TARGET_IA32e
#define MMODE XED_MACHINE_MODE_LONG_64
#define STACK_ADDR_WIDTH XED_ADDRESS_WIDTH_64b
#else
#define MMODE XED_MACHINE_MODE_LEGACY_32
#define STACK_ADDR_WIDTH XED_ADDRESS_WIDTH_32b
#endif	// XED

int get_disasm(ADDRINT addr, string& res);
size_t check_disasm(ADDRINT addr);
size_t check_disasm2(ADDRINT addr);
bool check_ins_valid(ADDRINT addr);

#endif	// COMMON_PIN_ANALYZER