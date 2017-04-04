// CV Analyzer 
// 2015.04.25. 
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
bool isMemTrace = false;
bool isInsTrace = false;
bool isDumpCode = false;

// lock serializes access to the output file.
PIN_LOCK lock;

// standard output & file output 
ostream * fout = &cerr;	// result output
ostream * dout = NULL;	// result output

// ===============
// for code cache
// ===============
map<ADDRINT, string> asmcode_m;
map<ADDRINT, vector<ADDRINT>*> trace_cache_m;
set<ADDRINT> trace_visited_s; 
map<ADDRINT, REG> op_cache_m;
UINT8 buf[1024];	// code cache buffer size is 1KB
char cbuf[256];	// character buffer


// obfuscated module information
ADDRINT obf_img_saddr = 0;	// section start address where EIP is changed into 
ADDRINT obf_img_eaddr = 0;
ADDRINT obf_txt_saddr = 0;	// section start address where EIP is changed into 
ADDRINT obf_txt_eaddr = 0;

// instruction trace start and end addresses
ADDRINT instrc_saddr = 0;
ADDRINT instrc_eaddr = 0;
BOOL instrc_detail = false;
bool isInsTrcWatchOn = false;
bool isInsTrcReady = false;
bool isInsTrcOn = false;
int analysis_step = 0;


// handler table information
map<ADDRINT, ADDRINT> hdl_addr_m;
map<ADDRINT, ADDRINT> rev_hdl_addr_m;

// tracing helper
mod_info_t *prevmod;
ADDRINT prevaddr;	// previous trace address

// region info 
vector<reg_info_t*> region_info_v;

// module info 
map<string, mod_info_t*> module_info_m;

// function info
map<ADDRINT, fn_info_t*> fn_info_m;


// Memory Trace Instrumentation
void EXE_TRC_Memtrc_analysis(ADDRINT addr, THREADID threadid);
void EXE_TRC_MemTrace_inst(TRACE trace, void *v);
void EXE_INS_Memtrace_MW_analysis(CONTEXT *ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack);
void EXE_INS_Memtrace_MW_after_analysis(CONTEXT *ctxt, size_t mSize, THREADID threadid, BOOL is_stack);
void EXE_INS_Memtrace_MR_analysis(CONTEXT *ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack);

// Instruction Trace Instrumentation
void EXE_Trace_Trc_ana(ADDRINT ip, THREADID threadid);
void EXE_TRC_InsTrc_Inst(TRACE trace, void *v);


ADDRINT toADDRINT(UINT8 *buf) {
	int n = sizeof(ADDRINT);
	ADDRINT addr = buf[n - 1];
	for (int i = n - 2; i >= 0; i--) {
		addr = (addr << 8) | buf[i];
	}
	return addr;
}

ADDRINT buf2val(UINT8 *buf, size_t n) {	
	ADDRINT addr = buf[n - 1];
	for (int i = n - 2; i >= 0; i--) {
		addr = (addr << 8) | buf[i];
	}
	return addr;
}