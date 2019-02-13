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
ADDRINT obf_rdata_eaddr = 0;	

ADDRINT obf_idata_saddr = 0;	// idata start
ADDRINT obf_idata_eaddr = 0;	// idata end

ADDRINT oep = 0;	// oep of VMProtect unpacked executable

/* ================================================================== */
// Global variables 
/* ================================================================== */

// thread count
size_t thr_cnt;
set<size_t> thread_ids;
PIN_THREAD_UID mainThreadUid;

// direct call
bool isDirectCall = false;

// code cache
map<ADDRINT, string> asmcode_m;
map<ADDRINT, vector<ADDRINT>*> trace_cache_m;
map<ADDRINT, ADDRINT> trace_next_addr_m;
UINT8 memory_buffer[1024*1024 * 100];	// code cache buffer size is 100MB


/////////////////////////////////////////////////////////////////
// structure information
/////////////////////////////////////////////////////////////////

ADDRINT obf_dll_entry_addr;	// VMProtect dll entry address

// dll loader information for obfuscated dll analysis
ADDRINT loader_saddr = 0;
ADDRINT loader_eaddr = 0;

bool is_unpack_started = false;	// dll unpack started

// trace related variables
ADDRINT prevaddr;	// previous trace address
int obfCallLevel = 0;	// flag for recording 1-level obfuscated call instructions

mod_info_t *prevmod;	// previous module

// KNOB related flags
bool isDLLAnalysis = false;

// obfuscated DLL name
string obf_dll_name = "";

// standard output & file output 
ostream * fout = &cerr;	// result output

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
map<ADDRINT, ADDRINT> iataddr2obffnaddr;


// obfuscated call information struct
struct call_info_t {
	bool is_push_before_call;	
	ADDRINT caller_addr;
	ADDRINT target_addr;
	call_info_t(bool chk1, ADDRINT caller, ADDRINT target) :
		is_push_before_call(chk1), caller_addr(caller), target_addr(target) {};
};

// obfuscated call instruction address and target address
vector<call_info_t*> obfuscated_call_candidate_addrs;
vector<pair<ADDRINT, ADDRINT>> obf_call_addrs;

// flags for current status 
bool isRegSaved = false;
bool isCheckAPIStart = false;
bool isCheckAPIRunning = false;
bool isFoundAPICalls = false;
size_t current_obf_fn_pos = 0;

// API pre-run trace recording
vector<ADDRINT> traceAddrSeq;
vector<ADDRINT> traceSPSeq;
map<REG, pair<ADDRINT, string>> movRegApiFnAddrs;

// ADDRINT caller_addr = 0;
call_info_t *current_obfuscated_call;

ADDRINT current_callstkaddr = 0;
bool isMovRegCallReg = false;
bool isCheckAPIEnd = false;

// current obfuscated function address for x64
ADDRINT current_obf_fn_addr;

// export block candidate
ADDRINT imp_start_addr = 0;
vector<ADDRINT> function_slots_in_rdata;

ADDRINT toADDRINT(UINT8 *buf) { 
	int n = ADDRSIZE;
	ADDRINT addr = buf[n-1];
	for (int i = n-2; i >= 0; i--) {
		addr = (addr << 8) | buf[i];
	}
	return addr; 
}

ADDRINT toADDRINT1(UINT8 *buf) { 
	int n = ADDRSIZE;
	ADDRINT addr = buf[n];
	for (int i = n - 1; i >= 1; i--) {
		addr = (addr << 8) | buf[i];
	}
	return addr;
}

#define RECORDTRACE 1

// registers used for obfuscation
#ifdef TARGET_IA32
REG regs_for_obfuscation[] = { REG_EAX, REG_EBX, REG_ECX, REG_EDX, REG_ESI, REG_EDI };
REG regs_ctx[] = { REG_EAX, REG_EBX, REG_ECX, REG_EDX, REG_ESI, REG_EDI, REG_ESP, REG_EBP };
#elif TARGET_IA32E
REG regs_for_obfuscation[] = { REG_RAX, REG_RBX, REG_RCX, REG_RDX, REG_RSI, REG_RDI };
REG regs_ctx[] = { REG_RAX, REG_RBX, REG_RCX, REG_RDX, REG_RSI, REG_RDI, REG_RSP, REG_RBP };
#endif	
map<REG, ADDRINT> regs_saved;


void clear_mwblocks();
void clear_meblocks();
ADDRINT blk2addr(unsigned blk);
bool set_mwblock(ADDRINT addr);
size_t get_mwblock(ADDRINT addr);
bool set_meblock(ADDRINT addr);
size_t get_meblock(ADDRINT addr);

void FindObfuscatedAPICalls();
bool FindGap();
void IMG_inst(IMG img, void *v);
void ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v);
void ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v);

void TRC_inst(TRACE trace, void *v);
void TRC_analysis(CONTEXT *ctxt, ADDRINT addr, UINT32 size, THREADID threadid);
void INS_MW_analysis(ADDRINT targetAddr, ADDRINT insaddr);
void save_regs(LEVEL_VM::CONTEXT * ctxt);
void restore_regs(LEVEL_VM::CONTEXT * ctxt);
REG check_api_fn_assignment_to_register(LEVEL_VM::CONTEXT * ctxt);
REG check_reg_call_ins(std::string &disasm);
bool check_abnormal_ins(std::string &disasm);
