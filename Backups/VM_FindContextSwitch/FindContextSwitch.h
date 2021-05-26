// Find Context Switch in VM
// 2019.11.15.~
// seogu.choi@gmail.com

#include "pin.H"
#include "StrUtil.h"
#include "PinSymbolInfoUtil.h"

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

// KNOB related flags
bool is_dll_analysis = false;

// obfuscated DLL name
string obf_dll_name = "";

// lock serializes access to the output file.
PIN_LOCK lock;

// standard output & file output 
ostream * fout = &cerr;	// result output

// instruction count and basic block count per thread
map<THREADID, size_t> ins_cnt;
map<THREADID, size_t> bbl_cnt;


// section helper
template<typename T>
constexpr auto IS_MAIN_IMG(T addr) { return (addr >= main_img_saddr && addr < main_img_eaddr); }

template<typename T>
constexpr auto IS_VM_SEC(T addr) { return(addr >= main_vm_saddr && addr < main_vm_eaddr); }

template<typename T>
constexpr auto IS_TEXT_SEC(T addr) { return(addr >= main_txt_saddr && addr < main_txt_eaddr); }

// obfuscated module information
mod_info_t *main_img_info;
ADDRINT main_img_saddr = 0;	// section start address where EIP is changed into 
ADDRINT main_img_eaddr = 0;
ADDRINT main_txt_saddr = 0;	// section start address where EIP is changed into 
ADDRINT main_txt_eaddr = 0;
ADDRINT main_vm_saddr = 0;
ADDRINT main_vm_eaddr = 0;

// loader and dll information for obfuscated dll analysis
ADDRINT obf_dll_entry_addr;	// dll entry address of obfuscated dll
ADDRINT loader_saddr = 0;
ADDRINT loader_eaddr = 0;

// VM information
struct VMContextSwitch {
	ADDRINT vmenter_addr = 0;
	ADDRINT vmexit_addr = 0;
};
vector<VMContextSwitch> vm_cs;

sec_info_t *vmsec;
size_t vmsec_name = 0;

// tracing helper
map <THREADID, ADDRINT> thr_prev_addr;	// previous trace address

// region info 
vector<reg_info_t*> region_info_v;

// module info 
map<string, mod_info_t*> module_info_m;

// function info
map<ADDRINT, fn_info_t*> fn_info_m;
map<pair<string, string>, fn_info_t*> fn_str_2_fn_info;

// Instrumentation and analysis functions
void Pintool_Instrument_IMG(IMG img, void* v);
void TRC_Instrument(TRACE trace, void* v);
void BBL_Analysis(CONTEXT* ctx, THREADID tid, ADDRINT saddr, ADDRINT eaddr);


ADDRINT buf2val(UINT8 *buf, size_t n) {	
	ADDRINT addr = buf[n - 1];
	for (int i = n - 2; i >= 0; i--) {
		addr = (addr << 8) | buf[i];
	}
	return addr;
}
