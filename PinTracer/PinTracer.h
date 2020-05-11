// Pin Tracer
// 2015.04.25. ~
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
bool isDLLAnalysis = false;
string isMemTrace = "";
bool isMemReadTrace = false;
bool isMemWriteTrace = false;
bool isCount = false;
bool isGraph = false;
bool isInsTrace = false;
bool isWriteExecute = false;
bool isBlockTraceHex = false;
bool isBlockTrace = false;
bool isBlockTracePT = true;
bool isAPITrace = false;
bool isMainAPITrace = false;
bool isDumpCode = false;
bool isVMAnalysis = false;
bool isVMPAnalysis = false;
bool isSkipAntiPin = false;

// VMP Analysis variables
bool isVMPChecking = false;

// obfuscated DLL name
string obf_dll_name = "";


// lock serializes access to the output file.
PIN_LOCK lock;

// standard output & file output 
ostream * fout = &cerr;	// result output
ostream* dot_out = NULL;	// dot output
ostream * dout = NULL;	// result output

// instruction count and basic block count per thread
map<THREADID, size_t> ins_cnt;
map<THREADID, size_t> bbl_cnt;


// ========================================================================================================================
// memory section write & execute check by block
// ========================================================================================================================
// memory write set
set<ADDRINT> mwaddrs;

// #define DEBUG 2
#define MAX_BLOCKS 100000	// Maximum File Size : 50MB assuming that default file alignment is 512 bytes (= 0.5kB)
#define BLOCK_SIZE 512
size_t mwblocks[MAX_BLOCKS];
size_t meblocks[MAX_BLOCKS];

// OEP candidates
vector<ADDRINT> oep_candidates;
bool add_oep_candidate(ADDRINT a) {	
	auto it = oep_candidates.begin();
	for (; it != oep_candidates.end(); it++) {
		if (*it == a) {			
			return false;
		}
	}
	oep_candidates.push_back(a);
	return true;
}
bool remove_oep_candidate(ADDRINT a) {
	auto it = oep_candidates.begin();
	for (; it != oep_candidates.end(); it++) {
		if (*it == a) {
			oep_candidates.erase(it);
			return true;
		}
	}
	return false;
}



// ===============
// for code cache
// ===============
map<ADDRINT, string> asmcode_m;
map<ADDRINT, vector<ADDRINT>*> trace_cache_m;
set<ADDRINT> trace_visited_s; 
UINT8 buf[1024];	// code cache buffer size is 1KB
char cbuf[256];	// character buffer


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
bool dll_is_unpack_started = false;	// dll unpack started

// instruction trace start and end addresses
ADDRINT instrc_saddr = 0;
ADDRINT instrc_eaddr = 0;
bool isInsTrcWatchOn = false;
bool isInsTrcReady = false;
bool isInsTrcOn = false;
int analysis_step = 0;

// instruction trace start api sequence
vector<string> trc_start_apis;
size_t current_api_match_pos;


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
ADDRINT vmexit_addr = 0;
sec_info_t *vmsec;
string vmsec_name = ".reloc";	// .reloc is Code Virtualizer's default section name

// handler table information
map<ADDRINT, ADDRINT> hdl_addr_m;
map<ADDRINT, ADDRINT> rev_hdl_addr_m;

// tracing helper
mod_info_t *prevmod;
sec_info_t *prevsec;
map <THREADID, ADDRINT> thr_prev_addr;	// previous trace address

// conditional branch target
// last_addr -> target_addr, next_addr
map <ADDRINT, pair<ADDRINT, ADDRINT>> bbl_cond_br_tgt;

// basic block that has indirect branch target
set <ADDRINT> bbl_has_indirect_br_tgt;		

// a basic block's last call/ret instruction
#ifdef GEN_PT_PKT
set <ADDRINT> bbl_last_ins_ret;
#endif

// basic block last instruction branch type
enum BB_LAST_INS_TYPE {
	BB_JMP_DIRECT = 1, 
	BB_JMP_INDIRECT,
	BB_JCC,
	BB_CALL_DIRECT, 
	BB_CALL_INDIRECT,
	BB_RET,	
	BB_OTHER, 
};

string BB_LAST_INS_TYPE_STR[] = {
	"", "JD", "JI", "JC", "CD", "CI", "RE", ""
};

map <ADDRINT, BB_LAST_INS_TYPE> bbl_last_ins_type;


// region info 
vector<reg_info_t*> region_info_v;

// module info 
map<string, mod_info_t*> module_info_m;

// function info
map<ADDRINT, fn_info_t*> fn_info_m;
map<pair<string, string>, fn_info_t*> fn_str_2_fn_info;

// Instrumentation and analysis functions
void IMG_Instrument(IMG img, void* v);
void TRC_Instrument(TRACE trace, void* v);

void BBL_Count(ADDRINT addr, ADDRINT bbl_size, ADDRINT num_ins, THREADID tid);
void BBL_CodeExecuted(ADDRINT addr, ADDRINT size, THREADID threadid);
void BBL_PT_CodeExecuted(ADDRINT addr, ADDRINT lastaddr, THREADID tid);
void INS_PT_WriteExecute(ADDRINT addr);
void INS_HandlerExit_Handler(ADDRINT addr, THREADID tid);
void TRC_APIOutput_Handler(ADDRINT addr, THREADID tid);

void INS_Print(CONTEXT* ctxt, ADDRINT addr, THREADID tid);
void BBL_Skip_ExeptionHandler(CONTEXT* ctxt, ADDRINT addr, ADDRINT toaddr, THREADID tid);

// Memory Trace Instrumentation

void INS_Memtrace_MR(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid);
void INS_Memtrace_MW_before(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid);
void INS_Memtrace_MW_after(CONTEXT* ctxt, size_t mSize, THREADID threadid);

void INS_Memtrace_MW_Handler(CONTEXT *ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack);
void INS_Memtrace_MWAfter_Handler(CONTEXT *ctxt, size_t mSize, THREADID threadid, BOOL is_stack);
void INS_Memtrace_MR_Handler(CONTEXT *ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack);

void INS_WriteExecuteTrace_MW(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid);


// Memory Read Write Helper
void clear_mwblocks();
void clear_meblocks();
ADDRINT blk2addr(unsigned blk);
bool set_mwblock(ADDRINT addr);
size_t get_mwblock(ADDRINT addr);
bool set_meblock(ADDRINT addr);
size_t get_meblock(ADDRINT addr);

// PE Header Information
ADDRINT get_exception_handler_jump_target(ADDRINT ex_va);


ADDRINT buf2val(UINT8 *buf, size_t n) {	
	ADDRINT addr = buf[n - 1];
	for (int i = n - 2; i >= 0; i--) {
		addr = (addr << 8) | buf[i];
	}
	return addr;
}

template<typename T>
constexpr auto IS_MAIN_IMG(T addr) { return (addr >= main_img_saddr && addr < main_img_eaddr); }

template<typename T>
constexpr auto IS_VM_SEC(T addr) { return(addr >= main_vm_saddr && addr < main_vm_eaddr); }

template<typename T>
constexpr auto IS_TEXT_SEC(T addr) { return(addr >= main_txt_saddr && addr < main_txt_eaddr); }


fn_info_t* prev_fn_info;
mod_info_t* prev_mod_info;

/// md5 hash
string get_bb_str(ADDRINT addr, size_t size);

/// node: (address | code bytes) string
/// edge: node -> node map

map<string, set<string>> dcfg, tr_dcfg;
map<THREADID, string> prev_node;
