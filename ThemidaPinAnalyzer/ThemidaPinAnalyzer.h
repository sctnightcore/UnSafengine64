#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include "StrUtil.h"
#include "PinSymbolInfoUtil.h"

// obfuscated module information
ADDRINT obf_img_saddr = 0;	// section start address where eip is changed into 
ADDRINT obf_img_eaddr = 0;
ADDRINT obf_txt_saddr = 0;	// section start address where eip is changed into 
ADDRINT obf_txt_eaddr = 0;
ADDRINT oep = 0;	// oep of themida unpacked executable

/* ================================================================== */
// Global variables 
/* ================================================================== */

bool isDetach = false;

// thread control
size_t thr_cnt;
set<size_t> thread_ids;
PIN_THREAD_UID mainThreadUid;

// ===============
// for debugging
// ===============
map<ADDRINT, string> asmcode_m;
map<ADDRINT, vector<ADDRINT>*> trace_cache_m;


ADDRINT obf_entry_addr;	// themida dll entry address

// dll loader information for obfuscated dll analysis
ADDRINT loader_saddr = 0;
ADDRINT loader_eaddr = 0;

bool is_unpack_started = false;	// dll unpack started

// trace related variables
ADDRINT prevaddr;	// previous trace address
int obfCallLevel = 0;	// flag for recording 1-level obfuscated call instructions

mod_info_t *prevmod;	// previous module

// KNOB related flags
bool isMemTrace = false;
bool isAPIDetect = false;
bool isDLLAnalysis = false;
bool isOEPDetect = false;
bool isDebug = false;

// obfuscated DLL name
string dll_name = "";

// standard output & file output 
ostream * fout = &cerr;	// result output
ostream * dout = NULL;	// result output

// number of seconds to wait until a debugger to attach at OEP
UINT32 debugger_attach_wait_time = 0;

// instruction trace start and end addresses
ADDRINT instrc_saddr = 0;
ADDRINT instrc_eaddr = 0;
bool isInsTrcWatchOn = false;
bool isInsTrcReady = false;
bool isInsTrcOn = false;

// anti-attach write addresses
set<ADDRINT> anti_attach_address_set;

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

// map from obfuscated address to original address in IAT
map<ADDRINT, ADDRINT> iataddr2obffnaddr;

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

void EXE64_FindAPICalls();
bool EXE64_CheckExportArea(int step);
void EXE64_CheckExportFunctions();
void EXE64_TRC_APIDetect_analysis(CONTEXT *ctxt, ADDRINT addr, THREADID threadid);
void EXE64_INS_APIDetect_MW_analysis(ADDRINT targetAddr);
void EXE64_TRC_APIDetect_inst(TRACE trace, void *v);

void CheckExportFunctions();
void EXE_IMG_inst(IMG img, void *v);
void DLL_IMG_inst(IMG img, void *v);
void ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v);
void ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v);
void EXE_TRC_Memtrc_analysis(ADDRINT addr, THREADID threadid);
void DLL_TRC_analysis(ADDRINT addr, THREADID threadid);
void EXE_TRC_inst(TRACE trace, void *v);
void DLL_TRC_inst(TRACE trace, void *v);
void EXE_INS_Memtrace_MW_analysis(ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid);
void EXE_INS_Memtrace_MR_analysis(ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid);
void DLL_INS_inst(INS ins, void *v);

void DLL64_TRC_inst(TRACE trace, void *v);
void DLL64_TRC_analysis(CONTEXT *ctxt, ADDRINT addr, THREADID threadid);
void DLL64_FixIAT();

void EXE_TRC_OEPDetect_inst(TRACE trace, void *v);
void EXE_TRC_OEPDetect_analysis(ADDRINT addr, THREADID threadid);
void EXE_INS_OEPDetect_MW_analysis(CONTEXT *ctxt, ADDRINT ip, ADDRINT nextip, size_t mSize, ADDRINT targetAddr, THREADID threadid);


void EXE_TRC_APIDetect_inst(TRACE trace, void *v);
void EXE_TRC_APIDetect_analysis(ADDRINT addr, THREADID threadid);
void EXE_INS_APIDetect_MW_analysis(CONTEXT *ctxt, ADDRINT ip, ADDRINT nextip, size_t mSize, ADDRINT targetAddr, THREADID threadid);
void EXE_INS_APIDetect_MR_analysis(ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid);
void DLL_INS_APIDetect_MW_analysis(ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid);
void DLL_INS_APIDetect_MR_analysis(ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid);

