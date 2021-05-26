// Common Pin Analyzer Tools 
// - Symbol Info Utility
// 2015.4.25. -2020.6.23.
// Seokwoo Choi
//

#ifndef PIN_HELPER
#define PIN_HELPER

#include <string>
#include "pin.H"
#include <set>
#include <map>
extern "C" {
#include "xed-interface.h"
}


// ========================================================================================================================
// Architecture 32/64
// ========================================================================================================================
#ifdef TARGET_IA32
constexpr auto ADDRSIZE = 4;
#else
constexpr auto ADDRSIZE = 8;
#endif


// ========================================================================================================================
// String Utility
// ========================================================================================================================
#define toHex4(val) StringHex(val, 8, false)
#define toHex8(val) hexstr(val, 8).substr(2)
#define	toHex1(val) StringHex(val, 2, false)

#ifdef TARGET_IA32
#define	toHex(val) toHex4(val)
#elif TARGET_IA32E
#define	toHex(val) toHex8(val)
#endif

#define TO_LOWER(str) transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { return std::tolower(c); })

ADDRINT buf2val(UINT8* buf, size_t n);

using std::vector;
using std::map;
using std::set;
using std::transform;
using std::pair;
using std::stringstream;
using std::istringstream;
using std::hex;
using std::string;
using std::endl;
using std::ostream;
using std::ofstream;
using std::ifstream;
using std::ios;
using std::copy;



// ========================================================================================================================
// File IO 
// ========================================================================================================================
extern ostream* fout;	// result output
extern PIN_LOCK lock;	// pin lock
extern map<ADDRINT, string> asmcode_m;	// code cache



// ========================================================================================================================
// ADDRINT utility
// ========================================================================================================================
#define TO_ADDRINT(buf) (*static_cast<const ADDRINT*>(static_cast<const void*>(buf)))
#define TO_UINT32(buf) (*static_cast<const UINT32*>(static_cast<const void*>(buf)))
#define ADDRINT_TO_BYTES(val, buf) copy(static_cast<const UINT8*>(static_cast<const void*>(&val)), static_cast<const UINT8*>(static_cast<const void*>(&val)) + ADDRSIZE, buf)


// ========================================================================================================================
// Symbol information
// ========================================================================================================================
enum ModuleType {
	mod_type_exe, mod_type_dll, mod_type_other
};

// function info
struct FunctionInformation {
	string module_name;
	string name;
	ADDRINT saddr, eaddr;
	set<ADDRINT> obf_addrs;	// for checking obfuscated code writing
	string GetDetailedName();
	FunctionInformation(string m, string n, ADDRINT sa, ADDRINT ea) :module_name(m), name(n), saddr(sa), eaddr(ea) {};
	bool operator==(const FunctionInformation&) const;
	bool operator!=(const FunctionInformation&) const;
};


// region info
struct RegionInformation {
	ADDRINT addr;
	size_t size;
	RegionInformation(ADDRINT sa, ADDRINT sz):addr(sa), size(sz) {};
	bool operator==(const RegionInformation &) const;
	bool operator!=(const RegionInformation &) const;
};

// section info
struct SectionInformation {
	string module_name;
	string name;
	ADDRINT saddr, eaddr;
	SectionInformation(string m, string n, ADDRINT sa, ADDRINT ea):module_name(m), name(n), saddr(sa), eaddr(ea) {};
	bool operator==(const SectionInformation &) const;
	bool operator!=(const SectionInformation &) const;
};

// module info
struct ModuleInformation {
	string name;
	string path;
	ModuleType type;
	ADDRINT saddr, eaddr;
	vector<SectionInformation*> sec_infos;
	vector<FunctionInformation*> fn_infos;
	bool isDLL() {
		return (type == mod_type_dll);
	}
	bool isEXE() {
		return (type == mod_type_exe);
	}
	ModuleInformation(string p, ADDRINT sa, ADDRINT ea):path(p), saddr(sa), eaddr(ea)  {
		size_t pos = p.rfind("\\") + 1;
		name = p.substr(pos);
		TO_LOWER(name);
		if (name.find(".exe") != string::npos) type = mod_type_exe;
		else if (name.find(".dll") != string::npos) type = mod_type_dll;
		else type = mod_type_other;
	}
	bool operator==(const ModuleInformation &) const;
	bool operator!=(const ModuleInformation &) const;
};

// output operators
std::ostream& operator<<(std::ostream &strm, const FunctionInformation &a);
std::ostream& operator<<(std::ostream &strm, const SectionInformation &a);
std::ostream& operator<<(std::ostream& strm, const RegionInformation& a);
std::ostream& operator<<(std::ostream &strm, const ModuleInformation &a);

// information getters
ModuleInformation *GetModuleInfo(ADDRINT addr);
RegionInformation *GetRegionInfo(ADDRINT addr);
SectionInformation *GetSectionInfo(ADDRINT addr);
SectionInformation *GetNextSectionInfo(ADDRINT addr);
FunctionInformation *GetFunctionInfo(ADDRINT addr);
FunctionInformation *GetFunctionInfo(string mod_name, string fn_name);
string GetAddrInfo(ADDRINT addr);

// module information
extern map<string, ModuleInformation*> module_info_m;
extern vector<RegionInformation*> region_info_v;
extern map<ADDRINT, FunctionInformation*> fn_info_m;
extern map<pair<string, string>, FunctionInformation*> fn_str_2_fn_info;


// ========================================================================================================================
// XED related
// ========================================================================================================================
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