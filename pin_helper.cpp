#include "pin_helper.h"
#include <sstream>
extern "C" {
#include "xed-interface.h"
}

using std::string;
using std::map;
using std::pair;
using std::stringstream;


// module info 
map<string, ModuleInformation*> module_info_m;
map<ADDRINT, ModuleInformation*> module_info_m1;

// function info
map<ADDRINT, FunctionInformation*> fn_info_m;
map<pair<string, string>, FunctionInformation*> fn_str_2_fn_info;


FunctionInformation::FunctionInformation(string m, string n, ADDRINT sa, ADDRINT ea) :module_name(m), name(n), saddr(sa), eaddr(ea) {	
	fn_info_m[sa] = this;
	auto mod = GetModuleInformation(m);
	if (mod) {
		mod->fn_infos.push_back(this);
	}	
};

// output operators
std::ostream& operator<<(std::ostream& strm, const FunctionInformation& a) {
	return strm << a.module_name << ":" << a.name << "[" << toHex(a.saddr) << "," << toHex(a.eaddr) << "]";
}

std::ostream& operator<<(std::ostream& strm, const SectionInformation& a) {
	return strm << a.name << "[" << toHex(a.saddr) << "," << toHex(a.eaddr) << "]";
}

std::ostream& operator<<(std::ostream& strm, const ModuleInformation& a) {
	return strm << a.path << "[" << toHex(a.saddr) << "," << toHex(a.eaddr) << "]";
}

FunctionInformation* ModuleInformation::get_function(ADDRINT addr)
{
	for (auto fn : fn_infos) {
		if (fn->saddr >= addr && addr < fn->eaddr) {
			return fn;
		}
	}
	return nullptr;
}

ModuleInformation::ModuleInformation(string p, ADDRINT sa, ADDRINT ea) :path(p), saddr(sa), eaddr(ea) {
	size_t pos = p.rfind("\\") + 1;
	name = p.substr(pos);
	TO_LOWER(name);
	if (name.find(".exe") != string::npos) type = mod_type_exe;
	else if (name.find(".dll") != string::npos) type = mod_type_dll;
	else type = mod_type_other;
	module_info_m[name] = this;
	for (ADDRINT i = sa / 0x1000; i < ea / 0x1000; i++) {
		module_info_m1[i] = this;
	}
}

ModuleInformation* GetModuleInformation(ADDRINT addr)
{
	return module_info_m1[addr / 0x1000];	
}

ModuleInformation* GetModuleInformation(string name)
{
	return module_info_m[name];	
}

SectionInformation* GetSectionInformation(ADDRINT addr)
{
	ModuleInformation* modinfo = GetModuleInformation(addr);
	if (modinfo == NULL) return NULL;
	for (const auto& secinfo : modinfo->sec_infos)
	{
		if (addr >= secinfo->saddr && addr < secinfo->eaddr)
		{
			return secinfo;
		}
	}
	return NULL;
}

FunctionInformation* GetFunctionInformationWithStartAddress(ADDRINT addr)
{
	ModuleInformation* modinfo = GetModuleInformation(addr);
	if (modinfo == NULL) return NULL;
	if (fn_info_m.find(addr) != fn_info_m.end())
	{
		return fn_info_m[addr];
	}
	return NULL;
}

FunctionInformation* GetFunctionInformation(ADDRINT addr)
{
	auto mod = GetModuleInformation(addr);	
	if (mod) {
		return mod->get_function(addr);;
	}
	return nullptr;
}

FunctionInformation* GetFunctionInformation(ModuleInformation* mod, ADDRINT addr)
{
	return mod->get_function(addr);
}

/// <summary> Try disassemble at the address and return the length of the disassembled instruciton. </summary>
int get_disasm(ADDRINT addr, string& res)
{

#if defined(TARGET_IA32E)
	static const xed_state_t dstate = { XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b };
#else
	static const xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b };
#endif
	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd, &dstate);

	const unsigned int max_inst_len = 15;

	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
	BOOL xed_ok = (xed_code == XED_ERROR_NONE);
	if (xed_ok) {
		char buf[2048];

		bool ok = xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, addr, 0, 0);
		if (ok) {
			res = string(buf);
			return xed_decoded_inst_get_length(&xedd);
		}
	}
	return 0;
}

bool ModuleInformation::operator==(const ModuleInformation& m) const
{
	return saddr == m.saddr;
}

bool SectionInformation::operator==(const SectionInformation& s) const
{
	return s.saddr == saddr;
}

bool FunctionInformation::operator==(const FunctionInformation& f) const
{
	return f.saddr == saddr;
}

bool ModuleInformation::operator!=(const ModuleInformation& m) const
{
	return saddr != m.saddr;
}

bool SectionInformation::operator!=(const SectionInformation& s) const
{
	return s.saddr != saddr;
}

bool FunctionInformation::operator!=(const FunctionInformation& f) const
{
	return f.saddr != saddr;
}

