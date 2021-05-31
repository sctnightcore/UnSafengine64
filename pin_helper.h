// Common Pin Analyzer Helper Tools 
// Seokwoo Choi

#ifndef PIN_HELPER
#define PIN_HELPER


#include <string>
#include "pin.H"
#include <set>
#include <map>
extern "C" {
#include "xed-interface.h"
}

using std::vector;
using std::set;
using std::transform;
using std::hex;
using std::string;
using std::ostream;
using std::copy;


// ===============================================================================================
// Architecture 32/64
// ===============================================================================================
#ifdef TARGET_IA32
constexpr auto ADDRSIZE = 4;
#else
constexpr auto ADDRSIZE = 8;
#endif

// ===============================================================================================
// Memory Read/Write
// ===============================================================================================
inline UINT8 GetBYTE(ADDRINT addr) {
	return *((UINT8*)addr);
}

inline UINT16 GetWORD(ADDRINT addr) {
	return *((UINT16*)addr);
}

inline UINT32 GetDWORD(ADDRINT addr) {
	return *((UINT32*)addr);
}

inline UINT64 GetQWORD(ADDRINT addr) {
	return *((UINT64*)addr);
}

inline void PutBYTE(ADDRINT addr, UINT8 val) {
	*((UINT8*)addr) = val;
}

inline void PutWORD(ADDRINT addr, UINT16 val) {
	*((UINT16*)addr) = val;
}

inline void PutDWORD(ADDRINT addr, UINT32 val) {
	*((UINT32*)addr) = val;
}

inline void PutQWORD(ADDRINT addr, UINT64 val) {
	*((UINT64*)addr) = val;
}

inline void PutBytes(ADDRINT dst, ADDRINT src, int len) {
	UINT8* psrc = (UINT8*)src;
	UINT8* pdst = (UINT8*)dst;
	for (int i = 0; i < len; i++) {
		*pdst++ = *psrc++;
	}
}


// ===============================================================================================
// String Utility
// ===============================================================================================
#define	toHex1(val) StringHex(val, 2, false)
#define	toHex2(val) StringHex(val, 4, false)
#define toHex4(val) StringHex(val, 8, false)
#define toHex8(val) hexstr(val, 8).substr(2)

#ifdef TARGET_IA32
#define	toHex(val) toHex4(val)
#elif TARGET_IA32E
#define	toHex(val) toHex8(val)
#endif

#define TO_LOWER(str) transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { return std::tolower(c); })


// ===============================================================================================
// File IO 
// =====================================================================================
extern ostream* fout;	// result output
extern PIN_LOCK lock;	// pin lock


// ===================================================================================
// ADDRINT utility
// ===================================================================================
#define TO_ADDRINT(buf) (*static_cast<const ADDRINT*>(static_cast<const void*>(buf)))
#define TO_UINT32(buf) (*static_cast<const UINT32*>(static_cast<const void*>(buf)))
#define ADDRINT_TO_BYTES(val, buf) copy(static_cast<const UINT8*>(static_cast<const void*>(&val)), static_cast<const UINT8*>(static_cast<const void*>(&val)) + ADDRSIZE, buf)


// =====================================================================================
// Symbol information
// =====================================================================================
enum ModuleType {
	mod_type_exe, mod_type_dll, mod_type_other
};

// function info
struct FunctionInformation {
	string module_name;
	string name;
	ADDRINT saddr, eaddr;
	FunctionInformation(string m, string n, ADDRINT sa, ADDRINT ea);
	bool operator==(const FunctionInformation&) const;
	bool operator!=(const FunctionInformation&) const;
};


// section info
struct SectionInformation {
	string module_name;
	string name;
	ADDRINT saddr, eaddr;
	SectionInformation(string m, string n, ADDRINT sa, ADDRINT ea) :module_name(m), name(n), saddr(sa), eaddr(ea) {};
	bool operator==(const SectionInformation&) const;
	bool operator!=(const SectionInformation&) const;
};

// module info
struct ModuleInformation {
	string name;
	string path;
	ModuleType type;
	ADDRINT saddr, eaddr;
	vector<SectionInformation*> sec_infos;
	vector<FunctionInformation*> fn_infos;
	FunctionInformation* get_function(ADDRINT addr);		
	ModuleInformation(string p, ADDRINT sa, ADDRINT ea);		
	bool operator==(const ModuleInformation&) const;
	bool operator!=(const ModuleInformation&) const;
};

// output operators
std::ostream& operator<<(std::ostream& strm, const FunctionInformation& a);
std::ostream& operator<<(std::ostream& strm, const SectionInformation& a);
std::ostream& operator<<(std::ostream& strm, const ModuleInformation& a);

// information getters
ModuleInformation* GetModuleInformation(ADDRINT addr);
ModuleInformation* GetModuleInformation(string name);
SectionInformation* GetSectionInformation(ADDRINT addr);
FunctionInformation* GetFunctionInformationWithStartAddress(ADDRINT addr);
FunctionInformation* GetFunctionInformation(ADDRINT addr);
FunctionInformation* GetFunctionInformation(ModuleInformation* mod, ADDRINT addr);

// ===============================================================================================
// XED related
// ===============================================================================================
#ifdef TARGET_IA32E
#define MMODE XED_MACHINE_MODE_LONG_64
#define STACK_ADDR_WIDTH XED_ADDRESS_WIDTH_64b
#else
#define MMODE XED_MACHINE_MODE_LEGACY_32
#define STACK_ADDR_WIDTH XED_ADDRESS_WIDTH_32b
#endif	// XED

int get_disasm(ADDRINT addr, string& res);

#endif