#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include "StrUtil.h"
#include "PinSymbolInfoUtil.h"

// obfuscated module information
ADDRINT main_img_saddr = 0;	// section start address where eip is changed into 
ADDRINT main_img_eaddr = 0;
ADDRINT main_txt_saddr = 0;	// section start address where eip is changed into 
ADDRINT main_txt_eaddr = 0;

ADDRINT obf_rdata_saddr = 0;	// section start address after .text section
ADDRINT obf_rdata_eaddr = 0;	// Added to keep compatibility with VMP deobfuscator

ADDRINT obf_idata_saddr = 0;	// idata start
ADDRINT obf_idata_eaddr = 0;	// idata end


ADDRINT oep = 0;	// oep of themida unpacked executable

/* ================================================================== */
// Global variables 
/* ================================================================== */

// thread control
size_t thr_cnt;
set<size_t> thread_ids;
PIN_THREAD_UID mainThreadUid;

// ===============
// for debugging
// ===============
map<ADDRINT, string> asmcode_m;
map<ADDRINT, vector<ADDRINT>*> trace_cache_m;

// Buffer
UINT8 memory_buffer[1024 * 1024 * 100];	// code cache buffer size is 100MB


ADDRINT obf_dll_entry_addr;	// themida dll entry address

// dll loader information for obfuscated dll analysis
ADDRINT loader_saddr = 0;
ADDRINT loader_eaddr = 0;

bool is_unpack_started = false;	// dll unpack started

// trace related variables
ADDRINT prevaddr;	// previous trace address
int obfCallLevel = 0;	// flag for recording 1-level obfuscated call instructions

mod_info_t *prevmod;	// previous module

/////////////////////////////////////////////////////////////////
// KNOB related flags
bool isDLLAnalysis = false;
string packer_type = "themida";

// obfuscated DLL name
string obf_dll_name = "";

// standard output & file output 
ostream * fout = &cerr;	// result output

// memory dump
bool isMemDump = false;

// direct call
bool isDirectCall = false;

/////////////////////////////////////////////////////////////////


// lock serializes access to the output file.
PIN_LOCK lock;

// region info 
vector<reg_info_t*> region_info_v;

// module info 
map<string, mod_info_t*> module_info_m;

// function info
map<ADDRINT, fn_info_t*> fn_info_m;
map<pair<string, string>, fn_info_t*> fn_str_2_fn_info;

// runtime function info
fn_info_t *current_obf_fn = NULL;

// map from obfuscated function into original function
map<ADDRINT, fn_info_t*> obfaddr2fn;

// map from obfuscated function into original function of 'mov esi, api' obfuscation
map<ADDRINT, fn_info_t*> mov_obfaddr2fn;

// map from obfuscated address to original address in IAT
map<ADDRINT, ADDRINT> addr2fnaddr;

// obfuscated call instruction address and target address
vector<pair<ADDRINT, ADDRINT>> obf_call_addrs;

// flags for current status 
bool isCheckAPIStart = false;
bool isCheckAPIRunning = false;
size_t current_obf_fn_pos = 0;
ADDRINT current_calladdr = 0;
ADDRINT current_callnextaddr = 0;
bool isCheckAPIEnd = false;

// current obfuscated function address for x64
ADDRINT current_obf_fn_addr;

// 64bit export block candidate
ADDRINT addrZeroBlk = 0;


#define MakeDWORD(buf) (buf[3] | (buf[2] << 8) | (buf[1] << 16) | (buf[0] << 24))
#define MakeADDR(buf) (buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24))
#define MakeADDR1(buf) (buf[1] | (buf[2] << 8) | (buf[3] << 16) | (buf[4] << 24))

ADDRINT toADDRINT(UINT8 *buf) { 
	int n = sizeof(ADDRINT);
	ADDRINT addr = buf[n-1];
	for (int i = n-2; i >= 0; i--) {
		addr = (addr << 8) | buf[i];
	}
	return addr; 
}

ADDRINT toADDRINT1(UINT8 *buf) { 
	int n = sizeof(ADDRINT);
	ADDRINT addr = buf[n];
	for (int i = n - 1; i >= 1; i--) {
		addr = (addr << 8) | buf[i];
	}
	return addr;
}

#define RECORDTRACE 1


void clear_mwblocks();
void clear_meblocks();
ADDRINT blk2addr(unsigned blk);
bool set_mwblock(ADDRINT addr);
size_t get_mwblock(ADDRINT addr);
bool set_meblock(ADDRINT addr);
size_t get_meblock(ADDRINT addr);

void dump_memory();

void ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v);
void ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v);

void FindAPICalls_x64();
bool CheckExportArea_x64(int step);

void CheckExportFunctions_x64();
void CheckExportFunctions_x86();

void TRC_analysis_x64(CONTEXT *ctxt, ADDRINT addr, THREADID threadid);
void INS_MW_analysis_x64(ADDRINT targetAddr);
void TRC_inst_x64(TRACE trace, void *v);

void IMG_inst(IMG img, void *v);

void DLL_TRC_inst(TRACE trace, void *v);
void DLL_INS_inst(INS ins, void *v);

void DLL64_TRC_inst(TRACE trace, void *v);
void DLL64_TRC_analysis(CONTEXT *ctxt, ADDRINT addr, THREADID threadid);
void DLL64_FixIAT();

void INS_inst(INS ins, void *v);
void INS_analysis(ADDRINT addr, THREADID threadid);
void INS_MW_analysis(size_t mSize, ADDRINT targetAddr);
void INS_MR_analysis(ADDRINT targetAddr);
