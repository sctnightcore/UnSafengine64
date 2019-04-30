// CV Analyzer 
// 2015.04.25. 
// seogu.choi@gmail.com

#include "Config.h"
#include "pin.H"
#include "StrUtil.h"
#include "PinSymbolInfoUtil.h"

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

// KNOB related flags
string isMemTrace = "";
bool isMemReadTrace = false;
bool isMemWriteTrace = false;
bool isInsTrace = false;
bool isBlockTrace = false;
bool isDumpCode = false;
bool isRegMemMap = false;

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
ADDRINT main_img_saddr = 0;	// section start address where EIP is changed into 
ADDRINT main_img_eaddr = 0;
ADDRINT main_txt_saddr = 0;	// section start address where EIP is changed into 
ADDRINT main_txt_eaddr = 0;

// instruction trace start and end addresses
ADDRINT instrc_saddr = 0;
ADDRINT instrc_eaddr = 0;
BOOL instrc_detail = false;
bool isInsTrcWatchOn = false;
bool isInsTrcReady = false;
bool isInsTrcOn = false;
int analysis_step = 0;

// registers used for obfuscation
#ifdef TARGET_IA32
REG pin_regs[] = { REG_EAX, REG_EBX, REG_ECX, REG_EDX, REG_ESI, REG_EDI, REG_EBP, REG_ESP };
#elif TARGET_IA32E
REG pin_regs[] = { 
	REG_RAX, REG_RBX, REG_RCX, REG_RDX, REG_RSI, REG_RDI, REG_RBP, REG_RSP, 
	REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15};
#endif	

// special values to find register-memory mapping
ADDRINT special_values[] = {
	0xAAAAAADD, 0xBAAAAAAD, 0xCAAAAAFE, 0xDEAAAAAD,	0xEEEEEE66, 0xF000000D,
	0xADD12345, 0xBAADBABE, 0xCAFEBABE, 0xDEADBEEF, 0xE664F00D, 0xF00DCAFE 
};

map<REG, ADDRINT> reg_2_special_value;
map<ADDRINT, REG> special_value_2_reg;

// VM information
ADDRINT vmenter_addr = 0;

// handler table information
map<ADDRINT, ADDRINT> hdl_addr_m;
map<ADDRINT, ADDRINT> rev_hdl_addr_m;

// tracing helper
mod_info_t *prevmod;
sec_info_t *prevsec;
ADDRINT prevaddr;	// previous trace address

// region info 
vector<reg_info_t*> region_info_v;

// module info 
map<string, mod_info_t*> module_info_m;

// function info
map<ADDRINT, fn_info_t*> fn_info_m;
map<pair<string, string>, fn_info_t*> fn_str_2_fn_info;


// Memory Trace Instrumentation
void EXE_TRC_Memtrc_analysis(ADDRINT addr, THREADID threadid);
void EXE_TRC_MemTrace_inst(TRACE trace, void *v);
void EXE_INS_Memtrace_MW_analysis(CONTEXT *ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack);
void EXE_INS_Memtrace_MW_after_analysis(CONTEXT *ctxt, size_t mSize, THREADID threadid, BOOL is_stack);
void EXE_INS_Memtrace_MR_analysis(CONTEXT *ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack);

// Instruction Trace Instrumentation
void EXE_TRC_InsTrc_Inst(TRACE trace, void *v);

// Register Memory Mapping Instrumentation
void EXE_Trc_RegMemMap_Ins(TRACE trc, void *v);
void EXE_Trc_RegMemMap_Ana(ADDRINT ip, THREADID threadid);
void EXE_INS_RegMemMap_vmenter_Ana(CONTEXT *ctxt, ADDRINT addr, THREADID threadid);
void EXE_INS_RegMemMap_before_Ana(CONTEXT *ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack);
void EXE_INS_RegMemMap_after_Ana(CONTEXT *ctxt, size_t mSize, THREADID threadid, BOOL is_stack);
void dump_registers(CONTEXT *ctxt, THREADID tid);

// Default block(=trace) tracing
void EXE_TRC_Blk_Inst(TRACE trace, void *v);
void EXE_BBL_Analysis(ADDRINT addr, ADDRINT size, THREADID threadid);
void EXE_INS_HandlerExit_Analysis(ADDRINT addr, THREADID tid);

int main(int argc, char * argv[]);


ADDRINT toADDRINT(UINT8 *buf) {
	int n = ADDRSIZE;
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

#define IS_MAIN_IMG(addr) (addr >= main_img_saddr && addr < main_img_eaddr)

fn_info_t* prev_fn_info;
mod_info_t* prev_mod_info;
