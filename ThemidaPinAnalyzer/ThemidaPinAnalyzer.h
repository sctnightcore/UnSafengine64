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

// internal threads
int current_resolve_api = -1;	// current resolve api thread number in internal thread
VOID unpack_thread(VOID *arg);	// unpack thread (main internal thread)
CONTEXT ctx0;

// code cache
map<ADDRINT, string> asmcode_m;

// trace cache
map<ADDRINT, vector<ADDRINT>*> trace_cache_m;
map<ADDRINT, ADDRINT> trace_next_addr_m;


// Buffer
UINT8 memory_buffer[1024 * 1024 * 100];	// code cache buffer size is 100MB


ADDRINT obf_dll_entry_addr;	// themida dll entry address

// dll loader information for obfuscated dll analysis
ADDRINT loader_saddr = 0;
ADDRINT loader_eaddr = 0;

bool is_unpack_started = false;	// dll unpack started


// trace related variables
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
// obf_call_candidate_addrss is a tuple of <call instruction address, opcode bytes, target address>
// opcode bytes are stored in ADDRINT type as follows 
// 
// call type 
// - direct_call : direct call. E8 __ __ __ __  
//   (relative addressing for x86)
// - indirect_call : indirect call using IAT. FF 15 __ __ __ __. call ds:[______] 
//                   ex) FF 15 dd cc bb aa -> call ds:[0xaabbccdd] 
//                      (absolute addressing to indirect address for x86)
//                   ex) FF 15 dd cc bb aa -> call ds:[0xaabbccdd + next_ip] 
//                      (relative addressing to indirect address for x64)
// - indirect_jmp : indirect jmp using IAT. FF 25 __ __ __ __. jmp ds:[______] 
//                  ex) FF 2F dd cc bb aa -> jmp ds:[0xaabbccdd]
//                  (absolute addressing to indirect address)
//                  ex) FF 15 dd cc bb aa -> jmp ds:[0xaabbccdd + next_ip] 
//                     (relative addressing to indirect address for x64)
// - indirect_mov : indirect mov using IAT. 
//     a1 : mov eax, ds : [・]
//     8b 05 : mov eax, ds : [・]
//     8b 1d : mov ebx, ds : [・]
//     8b 0d : mov ecx, ds : [・]
//     8b 15 : mov edx, ds : [・]
//     8b 35 : mov esi, ds : [・]
//     8b 3d : mov edi, ds : [・]
//    (absolute addressing to indirect address for x86)
//
//     48 8b 05 : mov rax, ds : [・]
//     48 8b 1d : mov rbx, ds : [・]
//     48 8b 0d : mov rcx, ds : [・]
//     48 8b 15 : mov rdx, ds : [・]
//     48 8b 35 : mov rsi, ds : [・]
//     48 8b 3d : mov rdi, ds : [・]
//    (relative addressing to indirect address for x64)
//


enum obf_call_type_t {
	DIRECT_CALL, INDIRECT_CALL, INDIRECT_JMP, INDIRECT_MOV
};


struct obf_call_t {
	obf_call_t(ADDRINT sa, ADDRINT da, obf_call_type_t it, string r, size_t g) : 
		srcaddr(sa), dstaddr(da), ins_type(it), reg(r), prev_push_inst_size(g) {};
	ADDRINT srcaddr;
	union {
		ADDRINT dstaddr;
		ADDRINT indaddr;
	};	
	obf_call_type_t ins_type;
	string reg;
	size_t prev_push_inst_size;

	size_t to_bytes(UINT8* byts) {
		ADDRINT reladdr;
		switch (ins_type) {
		case DIRECT_CALL:
			byts[0] = 0xe8;			
			reladdr = dstaddr - (srcaddr + 5);
			ADDRINT_TO_BYTES(reladdr, byts + 1);
			return 5;
		case INDIRECT_CALL:
			byts[0] = 0xff;
			byts[1] = 0x1f;
			if (ADDRSIZE == 4) {				
				ADDRINT_TO_BYTES(dstaddr, byts + 2);
			}
			else {
				reladdr = indaddr - (srcaddr + 6);
				ADDRINT_TO_BYTES(dstaddr, byts + 2);
			}
			return 6;
		case INDIRECT_JMP:
			byts[0] = 0xff;
			byts[1] = 0x2f;
			if (ADDRSIZE == 4) {
				ADDRINT_TO_BYTES(dstaddr, byts + 2);
			} 
			else {
				reladdr = indaddr - (srcaddr + 6);
				ADDRINT_TO_BYTES(reladdr, byts + 2);
			}
			return 6;
		case INDIRECT_MOV:			
			if (ADDRSIZE == 4) {
				byts[0] = 0x8b;
				if (reg == "eax") byts[1] = 0x05;
				else if (reg == "ebx") byts[1] = 0x1d;
				else if (reg == "ecx") byts[1] = 0x0d;
				else if (reg == "edx") byts[1] = 0x15;
				else if (reg == "esi") byts[1] = 0x35;
				else if (reg == "edi") byts[1] = 0x3d;																
				ADDRINT_TO_BYTES(dstaddr, byts + 2);
				return 6;
			}
			else {	// 64bit
				byts[0] = 0x48;
				byts[1] = 0x8b;
				if (reg == "rax") byts[2] = 0x05;
				else if (reg == "rbx") byts[2] = 0x1d;
				else if (reg == "rcx") byts[2] = 0x0d;
				else if (reg == "rdx") byts[2] = 0x15;
				else if (reg == "rsi") byts[2] = 0x35;
				else if (reg == "rdi") byts[2] = 0x3d;
				reladdr = indaddr - (srcaddr + 7);
				ADDRINT_TO_BYTES(reladdr, byts + 3);
				return 7;
			}		
		}
		return 0;
	}
};

vector<obf_call_t> obf_call_candidate_addrs;

std::ostream& operator<<(std::ostream &strm, const obf_call_t &a) {
	switch (a.ins_type) {
	case DIRECT_CALL:
		return strm << "direct call " << toHex(a.srcaddr) << "->" << toHex(a.dstaddr) << " push_size:" << a.prev_push_inst_size;
	case INDIRECT_CALL:
		return strm << "indirect call " << toHex(a.srcaddr) << "->" << toHex(a.dstaddr) << " push_size:" << a.prev_push_inst_size;;
	case INDIRECT_JMP:
		return strm << "indirect jmp " << toHex(a.srcaddr) << "->" << toHex(a.dstaddr) << " push_size:" << a.prev_push_inst_size;;
	case INDIRECT_MOV:
		return strm << "indirect mov " << toHex(a.srcaddr) << "->" << toHex(a.dstaddr) << " " << a.reg << " push_size:" << a.prev_push_inst_size;;
	default:
		return strm;
	}
}

// flags for current status 
bool isRegSaved = false;
bool isCheckAPIStart = false;
bool isCheckAPIRunning = false;
size_t current_obf_fn_pos = 0;
ADDRINT current_calladdr = 0;
ADDRINT current_callnextaddr = 0;
bool isCheckAPIEnd = false;

// current obfuscated function address for x64
ADDRINT current_obf_fn_addr;

// 64bit export block candidate
ADDRINT imp_start_addr = 0;
ADDRINT imp_end_addr = 0;
vector<fn_info_t*> imp_list;
bool found_IAT = false;
bool found_zero_blk = false;

// API pre-run trace recording
vector<ADDRINT> traceAddrSeq;
vector<ADDRINT> traceSPSeq;
map<REG, pair<ADDRINT, string>> movRegApiFnAddrs;

obf_call_t *current_obfuscated_call;

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

void save_regs(LEVEL_VM::CONTEXT * ctxt);
void restore_regs(LEVEL_VM::CONTEXT * ctxt);



void dump_memory();

void FindObfuscatedAPICalls();
bool FindIATArea();
void PrintIATArea();

// Pintool Instrumentation and Analysis Functions
void ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v);
void ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v);
void IMG_inst(IMG img, void *v);
void INS_inst(INS ins, void *v);
void INS_analysis(CONTEXT *ctxt, ADDRINT addr, THREADID threadid);
void INS_MW_analysis(size_t mSize, ADDRINT targetAddr);
void INS_MR_analysis(ADDRINT targetAddr);
void TRC_analysis(CONTEXT *ctxt, ADDRINT addr, THREADID threadid);
void TRC_inst(TRACE trace, void *v);

// Memory Read Write Helper
void clear_mwblocks();
void clear_meblocks();
ADDRINT blk2addr(unsigned blk);
bool set_mwblock(ADDRINT addr);
size_t get_mwblock(ADDRINT addr);
bool set_meblock(ADDRINT addr);
size_t get_meblock(ADDRINT addr);
