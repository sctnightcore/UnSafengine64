// Pin Tracer (for Obfuscated Binary)
// Author: seogu.choi@gmail.com
// Date: 2015.4.25. ~ 

#include "TheTracer.h"
using namespace std;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobDLLFile(KNOB_MODE_WRITEONCE, "pintool", "dll", "", "specify packed dll file");
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "output", "", "specify file name for the result");
KNOB<string> KnobMemoryTrace(KNOB_MODE_WRITEONCE, "pintool", "mem", "", "specify whether to trace memory read(r), write(w), read/write(rw)");

KNOB<bool> KnobWriteExecute(KNOB_MODE_WRITEONCE, "pintool", "wx", "", "specify whether to trace basic blocks that is written and executed");

KNOB<bool> KnobBlockTraceHex(KNOB_MODE_WRITEONCE, "pintool", "bbhex", "", "specify whether to trace basic blocks execution and write basic block hex code");
KNOB<bool> KnobBlockTrace(KNOB_MODE_WRITEONCE, "pintool", "bb", "", "specify whether to trace basic blocks execution");

KNOB<bool> KnobAPITrace(KNOB_MODE_WRITEONCE, "pintool", "api", "", "specify whether to trace api execution");
KNOB<bool> KnobMainAPITrace(KNOB_MODE_WRITEONCE, "pintool", "mainapi", "", "specify whether to trace api execution of main image");

KNOB<bool> KnobInstructionTrace(KNOB_MODE_WRITEONCE, "pintool", "ins", "0", "instruction trace");
KNOB<string> KnobTraceStartAddr(KNOB_MODE_WRITEONCE, "pintool", "saddr", "0", "instruction trace start address");
KNOB<string> KnobTraceEndAddr(KNOB_MODE_WRITEONCE, "pintool", "eaddr", "0", "instruction trace end address");
KNOB<string> KnobTraceStartAPIs(KNOB_MODE_WRITEONCE, "pintool", "sapiseq", "", "instruction trace starting api sequence");

KNOB<bool> KnobFindHandlerAddress(KNOB_MODE_WRITEONCE, "pintool", "1", "0", "1st step: find handler candidate addresses");
KNOB<bool> KnobVMAnalysis(KNOB_MODE_WRITEONCE, "pintool", "vmanalysis", "0", "VM analysis");
KNOB<string> KnobVMSection(KNOB_MODE_WRITEONCE, "pintool", "vmsection", ".vmp1", "specify vm section name");

KNOB<bool> KnobVMPAnalysis(KNOB_MODE_WRITEONCE, "pintool", "vmp", "0", "vmprotect internal vm analysis");

KNOB<bool> KnobSkipAntiDBI(KNOB_MODE_WRITEONCE, "pintool", "skipanti", "0", "Skip anti-dbi");


string get_bb_str(ADDRINT addr, size_t size) {	
	string ret_val = toHex(addr - main_img_saddr) + '_';
	PIN_SafeCopy(buff, (VOID*)addr, size);	

	for (size_t i = 0; i < size; i++)
	{
		ret_val += toHex1(buff[i]);		
	}			
	return ret_val;
}


////////////////////////////////////////////
// memory read / write / execute helper
////////////////////////////////////////////

void clear_mwblocks()
{
	memset(mwblocks, 0, MAX_BLOCKS);
}

void clear_meblocks()
{
	memset(meblocks, 0, MAX_BLOCKS);
}

ADDRINT blk2addr(unsigned blk)
{
	return main_img_saddr + blk * BLOCK_SIZE;
}

// memory write check
bool set_mwblock(ADDRINT addr)
{
	size_t idx = (addr - main_img_saddr) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;

	// if this block is previously executed, set meblock to zero
	if (meblocks[idx] > 0)
	{
		meblocks[idx] = 0;
		// *fout << "# "  << toHex(addr) << " is rewritten after execution." << endl;		
	}

	mwblocks[idx]++;
	return true;
}

size_t get_mwblock(ADDRINT addr)
{
	size_t idx = (addr - main_img_saddr) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;
	return mwblocks[idx];
}

// memory execute check
bool set_meblock(ADDRINT addr)
{
	size_t idx = (addr - main_img_saddr) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;
	meblocks[idx]++;
	return true;
}

size_t get_meblock(ADDRINT addr)
{
	size_t idx = (addr - main_img_saddr) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;
	return meblocks[idx];
}

typedef union _UNWIND_CODE {
	struct {
		UINT8 CodeOffset;
		UINT8 UnwindOP : 4;
		UINT8 OpInfo : 4;
	};
	UINT16 FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO_HDR {
	UINT8 Version : 3, Flags : 5;
	UINT8 SizeOfProlog;
	UINT8 CountOfCodes;
	UINT8 FrameRegister : 4, FrameOffset : 4;	
	UNWIND_CODE UnwindCode[1];
} UNWIND_INFO_HDR, *PUNWIND_INFO_HDR;

ADDRINT get_exception_handler_jump_target(ADDRINT ex_va)
{
#if TARGET_IA32E
	ADDRINT img_base = main_img_saddr;		
	ADDRINT ex_rva = ex_va - img_base;
	
	NW::PIMAGE_DOS_HEADER dos0 = (NW::PIMAGE_DOS_HEADER)img_base;
	NW::PIMAGE_NT_HEADERS nt0 = (NW::PIMAGE_NT_HEADERS)(img_base + dos0->e_lfanew);
		
	ADDRINT edir0 = nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
	ADDRINT edir_size = nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
	edir0 += img_base;
	
	*fout << "EXC DIR:" << toHex(edir0) << endl;
	*fout << "ex_rva:" << toHex(ex_rva) << endl;
	
	// check ExceptionDir


	ADDRINT unwind_info_rva = 0;
	for (ADDRINT rfaddr = edir0; rfaddr < edir0 + edir_size; rfaddr += sizeof(NW::RUNTIME_FUNCTION)) {
		NW::PRUNTIME_FUNCTION rf = NW::PRUNTIME_FUNCTION(rfaddr);
		*fout << toHex(rfaddr) << ' ' << toHex((ADDRINT)rf->BeginAddress) << ' ' << toHex((ADDRINT)rf->EndAddress) << endl;
		if (ex_rva >= rf->BeginAddress && ex_rva < rf->EndAddress) {
			unwind_info_rva = rf->UnwindInfoAddress;
			break;
		}
	}
	
	*fout << "UNWIND_INFO " << toHex(unwind_info_rva) << endl;

	if (!unwind_info_rva) return 0;
	
	// skip UNWIND_INFO
	PUNWIND_INFO_HDR unwind_info_hdr0 = (PUNWIND_INFO_HDR)(unwind_info_rva + img_base);	

	*fout << "UNWIND_INFO_HDR " << toHex(unwind_info_hdr0) << endl;
	*fout << "SIZE UNWIND_CODE " << sizeof(UNWIND_CODE) << endl;
	*fout << "COUNT UNWIND_CODE " << (ADDRINT)unwind_info_hdr0->CountOfCodes << endl;
	*fout << "first UNWIND CODE " << toHex(unwind_info_hdr0->UnwindCode) << endl;
	*fout << unwind_info_hdr0->CountOfCodes * sizeof(UNWIND_CODE) << endl;
	ADDRINT addrExceptionInfo = (ADDRINT)(unwind_info_hdr0->UnwindCode + unwind_info_hdr0->CountOfCodes);
	if (unwind_info_hdr0->CountOfCodes % 2 == 1) {
		addrExceptionInfo += 2;	// alignment to DWORD
	}	
	NW::PSCOPE_TABLE_AMD64 scope_table = (NW::PSCOPE_TABLE_AMD64) 
		(addrExceptionInfo + 4);	
		
	*fout << "SCOPE_TABLE " << toHex(scope_table) << endl;
	*fout << "COUNT " << scope_table->Count << endl;

	// check C_SCOPE_TABLE
	for (size_t i = 0; i < scope_table->Count; i++) {
		*fout << "BeginAddress:" << toHex((ADDRINT)scope_table->ScopeRecord[i].BeginAddress) 
			<< " EndAddress:" << toHex((ADDRINT)scope_table->ScopeRecord[i].EndAddress)
			<< " JumpTarget:" << toHex((ADDRINT)scope_table->ScopeRecord[i].JumpTarget) << endl;
		if (ex_rva >= scope_table->ScopeRecord[i].BeginAddress && ex_rva < scope_table->ScopeRecord[i].EndAddress) {
			*fout << "JumpTarget found " << toHex((ADDRINT)scope_table->ScopeRecord[i].JumpTarget) << endl;
			return scope_table->ScopeRecord[i].JumpTarget;			
		}
	}
	
#endif

#if TARGET_IA32
	return ex_va + 0xe;
#endif
	// cannot reach here
	return 0;
}


void INS_WriteExecuteTrace_MW(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid)
{
	if (get_meblock(targetAddr) > 1) {
		*fout << "Executed address " << 
			toHex(targetAddr- main_img_saddr) << '~' << toHex(targetAddr + mSize - main_img_saddr) << 
			" is rewritten at " << toHex(ip) << endl;
		remove_oep_candidate(targetAddr - main_img_saddr);		
	}
	set_mwblock(targetAddr);	
	
	// Check only main image to detect OEP
	if (!IS_MAIN_IMG(targetAddr)) return;

#if DEBUG == 1
	* fout << "# Write: " << toHex(targetAddr) << ' ' << *current_obf_fn << endl;
#endif
}

void TRC_WriteExecute(ADDRINT addr, THREADID tid)
{
	set_meblock(addr);
	if (IS_TEXT_SEC(addr))
	{
		if (get_mwblock(addr) && get_meblock(addr) == 1)
		{

			// ENIGMA 6.x x86: read 6 bytes and check whether this is Fake OEP
			// fake OEP pattern: EB 03 45 DC 9A C3
			// EB 03 __ __ __ C3 : jmp $+3; ... ; ret
			// Skip fake OEP

			PIN_SafeCopy(buff, (VOID*)addr, 6);
			for (auto pt: buff) 
				*fout << toHex1(pt) << ' ';
			*fout << endl;
			if (buff[0] == 0xEB && buff[1] == 0x03 && buff[5] == 0xC3) 
				return;

			ADDRINT oep = addr - main_img_saddr;
			add_oep_candidate(oep);
			*fout << "OEP Candidate:" << toHex(oep) << endl;			
			if (oep_candidates.size() > 5) {
				*fout << "Final OEP Candidates" << endl;
				for (auto a : oep_candidates) {
					*fout << toHex(a) << endl;
				}
				((ofstream*)fout)->close();
				PIN_ExitProcess(-1);
			}
		}
		return;
	}
}

//////////////////////////////


// Block Trace Functions
void TRC_Instrument(TRACE trc, void* v)
{
	ADDRINT addr = TRACE_Address(trc);


	if (isAPITrace || isMainAPITrace) {
		TRACE_InsertCall(trc, IPOINT_BEFORE, (AFUNPTR)TRC_APIOutput_Handler,
			IARG_ADDRINT, addr,
			IARG_THREAD_ID,
			IARG_END);
	}

	if (isSkipAntiPin) {
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			ADDRINT bbl_addr = BBL_Address(bbl);
			size_t bbl_size = BBL_Size(bbl);
			INS ins = BBL_InsHead(bbl);
#if TARGET_IA32E
			if (INS_Mnemonic(ins) == "POPFQ") {
				ADDRINT jmptgt = get_exception_handler_jump_target(bbl_addr);
				*fout << "Jump Target: " << toHex(jmptgt) << endl;
				if (jmptgt != 0) {
					INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE, (AFUNPTR)BBL_Skip_ExeptionHandler,
						IARG_CONTEXT,
						IARG_INST_PTR,
						IARG_ADDRINT, jmptgt + main_img_saddr,
						IARG_THREAD_ID,
						IARG_END);
		}
	}
#elif TARGET_IA32
			if (INS_Mnemonic(ins) == "POPFD" && bbl_size == 1) {
				ADDRINT jmptgt = get_exception_handler_jump_target(bbl_addr);
				if (jmptgt != 0) {
					*fout << toHex(bbl_addr) << " POPFD" << endl;

					BBL_InsertCall(
						bbl, IPOINT_BEFORE, (AFUNPTR)BBL_Skip_ExeptionHandler,
						IARG_CONTEXT,
						IARG_ADDRINT, bbl_addr,
						IARG_ADDRINT, jmptgt + main_img_saddr,
						IARG_THREAD_ID,
						IARG_END);
				}
			}			
#endif
		}	// end of for bbl
	}

	// skip dll module
	mod_info_t* mod_info = GetModuleInfo(addr);
	mod_info_t* prev_mod_info = prevmod;

	prevmod = mod_info;
	if (mod_info == NULL) return;
	if (mod_info->isDLL() && prev_mod_info != NULL && !IS_MAIN_IMG(prev_mod_info->saddr)) return;

	// vmp analysis
	if (isVMPAnalysis) {

		// OEP Detection
		if (IS_MAIN_IMG(addr)) {
			TRACE_InsertCall(trc, IPOINT_BEFORE, (AFUNPTR)TRC_WriteExecute,
				IARG_ADDRINT, addr,
				IARG_THREAD_ID,
				IARG_END);

			for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
				for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
					if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins)) {
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)INS_WriteExecuteTrace_MW,
							IARG_CONTEXT,
							IARG_INST_PTR,
							IARG_MEMORYWRITE_SIZE,
							IARG_MEMORYWRITE_EA,
							IARG_THREAD_ID,
							IARG_END);
					}
				}
			}
		}

		if (mod_info != NULL) {
			auto fn = GetFunctionInfo(addr);
			if (fn != NULL && fn->name == "ZwMapViewOfSection") {
				isVMPChecking = true;
				*fout << "# VMP Memory Checking Started" << endl;
			}
			if (fn != NULL && fn->name == "ZwUnmapViewOfSection") {
				isVMPChecking = false;
				*fout << "# VMP Memory Checking Ended" << endl;
			}
		}

		if (isVMPChecking) {
			if (IS_MAIN_IMG(addr) || mod_info == NULL) {
				for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
					for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
						if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins)) {
							INS_InsertPredicatedCall(
								ins, IPOINT_BEFORE, (AFUNPTR)INS_Memtrace_MW_before,
								IARG_CONTEXT,
								IARG_INST_PTR,
								IARG_MEMORYWRITE_SIZE,
								IARG_MEMORYWRITE_EA,
								IARG_THREAD_ID,
								IARG_END);
							INS_InsertPredicatedCall(
								ins, IPOINT_AFTER, (AFUNPTR)INS_Memtrace_MW_after,
								IARG_CONTEXT,
								IARG_MEMORYWRITE_SIZE,
								IARG_THREAD_ID,
								IARG_END);
						}
						if (INS_IsMemoryRead(ins) && !INS_IsStackRead(ins)) {
							INS_InsertPredicatedCall(
								ins, IPOINT_BEFORE, (AFUNPTR)INS_Memtrace_MR,
								IARG_CONTEXT,
								IARG_INST_PTR,
								IARG_MEMORYREAD_SIZE,
								IARG_MEMORYREAD_EA,
								IARG_THREAD_ID,
								IARG_END);
						}
					}
					INS ins = BBL_InsTail(bbl);
					if (IS_VM_SEC(addr) && INS_IsIndirectControlFlow(ins))
					{
						ADDRINT ins_addr = INS_Address(ins);
						string disasm_code = INS_Disassemble(ins);
						asmcode_m[ins_addr] = disasm_code;

						INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INS_HandlerExit_Handler,
							IARG_ADDRINT, ins_addr,
							IARG_THREAD_ID,
							IARG_END);
					}
				}
			}
		}
	}

	if (isWriteExecute && IS_MAIN_IMG(addr)) {
		TRACE_InsertCall(trc, IPOINT_BEFORE, (AFUNPTR)TRC_WriteExecute,
			IARG_ADDRINT, addr,
			IARG_THREAD_ID,
			IARG_END);
	}

	if (isInsTrace || isBlockTraceHex || isBlockTrace || isWriteExecute || isMemWriteTrace || isVMAnalysis) {
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			ADDRINT bbl_addr = BBL_Address(bbl);
			size_t bbl_size = BBL_Size(bbl);

			if (isInsTrace && IS_MAIN_IMG(bbl_addr)) {
				for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
					INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE, (AFUNPTR)INS_Print,
						IARG_CONTEXT,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_END);
				}
			}

			// print code cache
			if (isBlockTraceHex) {
				if (IS_MAIN_IMG(bbl_addr)) {
					PIN_SafeCopy(buff, (VOID*)bbl_addr, bbl_size);
					*fout << "C " << toHex(bbl_addr) << ' ' << toHex(bbl_size) << ' ';
					for (size_t i = 0; i < bbl_size; i++)
					{
						*fout << toHex1(buff[i]);
					}
					*fout << endl;
				}
			}

			if (isBlockTrace) {
				BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)BBL_CodeExecuted,
					IARG_ADDRINT, bbl_addr,
					IARG_ADDRINT, bbl_size,
					IARG_THREAD_ID,
					IARG_END);

			}


			// log jmp dword ptr [...] instruction
			// log jmp exx instruction
			// log ret instruction in vm section	


			if (isWriteExecute || isMemWriteTrace || isVMAnalysis) {
				for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
				{
					if (isWriteExecute && INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins)) {
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)INS_WriteExecuteTrace_MW,
							IARG_CONTEXT,
							IARG_INST_PTR,
							IARG_MEMORYWRITE_SIZE,
							IARG_MEMORYWRITE_EA,
							IARG_THREAD_ID,
							IARG_END);
					}


					if (isMemWriteTrace && INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins)) {
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)INS_Memtrace_MW_before,
							IARG_CONTEXT,
							IARG_INST_PTR,
							IARG_MEMORYWRITE_SIZE,
							IARG_MEMORYWRITE_EA,
							IARG_THREAD_ID,
							IARG_END);
						INS_InsertPredicatedCall(
							ins, IPOINT_AFTER, (AFUNPTR)INS_Memtrace_MW_after,
							IARG_CONTEXT,
							IARG_MEMORYWRITE_SIZE,
							IARG_THREAD_ID,
							IARG_END);
					}

					if (isVMAnalysis && IS_VM_SEC(addr) && (INS_IsRet(ins) || INS_IsIndirectBranchOrCall(ins)))
					{
						ADDRINT ins_addr = INS_Address(ins);
						string disasm_code = INS_Disassemble(ins);
						asmcode_m[ins_addr] = disasm_code;

						INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INS_HandlerExit_Handler,
							IARG_ADDRINT, ins_addr,
							IARG_THREAD_ID,
							IARG_END);
					}

					// Memory Read and Write
					if (isVMAnalysis) {
						UINT32 memOperands = INS_MemoryOperandCount(ins);
						for (UINT32 memOp = 0; memOp < memOperands; memOp++)
						{
							if (INS_MemoryOperandIsRead(ins, memOp) && !INS_IsStackRead(ins))
							{
								INS_InsertPredicatedCall(
									ins, IPOINT_BEFORE, (AFUNPTR)INS_Memtrace_MR_Handler,
									IARG_CONTEXT,
									IARG_INST_PTR,
									IARG_MEMORYREAD_SIZE,
									IARG_MEMORYREAD_EA,
									IARG_THREAD_ID,
									IARG_BOOL, INS_IsStackRead(ins),
									IARG_END);
							}
							if (INS_MemoryOperandIsWritten(ins, memOp) && !INS_IsStackWrite(ins))
							{
								INS_InsertPredicatedCall(
									ins, IPOINT_BEFORE, (AFUNPTR)INS_Memtrace_MW_Handler,
									IARG_CONTEXT,
									IARG_INST_PTR,
									IARG_MEMORYWRITE_SIZE,
									IARG_MEMORYWRITE_EA,
									IARG_THREAD_ID,
									IARG_BOOL, INS_IsStackWrite(ins),
									IARG_END);
								INS_InsertPredicatedCall(
									ins, IPOINT_AFTER, (AFUNPTR)INS_Memtrace_MWAfter_Handler,
									IARG_CONTEXT,
									IARG_MEMORYWRITE_SIZE,
									IARG_THREAD_ID,
									IARG_BOOL, INS_IsStackWrite(ins),
									IARG_END);
							}
						}
					}
				}
			}

		}

	}
}

void BBL_CodeExecuted(ADDRINT addr, ADDRINT size, THREADID tid)
{	

	// trace only main image
	if (!IS_MAIN_IMG(addr)) return;

	PIN_GetLock(&lock, tid + 1);
	// *fout << "B " << tid << ' ' << toHex(addr) << ' ' << GetAddrInfo(addr) << endl;		
	*fout << "B " << toHex(addr) << endl;
	PIN_ReleaseLock(&lock);
}


// packet count
size_t packet_no = 0;

// process PT TNT packet
char tntss[7];
size_t tntss_ptr = 0;
#define PUT_TNT_PACKET(x) \
	tntss[tntss_ptr++] = x; \
	if (tntss_ptr == 6) { \
		PIN_GetLock(&lock, tid + 1); \
		*fout << toHex4(packet_no++) << " tnt.8 " << tntss << endl; \
		PIN_ReleaseLock(&lock); \
		tntss_ptr = 0; \
	} 
#define PRINT_TNT_STR() \
	if (tntss_ptr > 0) { \
		tntss[tntss_ptr] = 0; \
		PIN_GetLock(&lock, tid + 1); \
		*fout << toHex4(packet_no++) << " tnt.8 " << tntss << endl; \
		PIN_ReleaseLock(&lock); \
		tntss_ptr = 0; \
	}

// bbl count
size_t bbl_no = 0;

void BBL_PT_CodeExecuted(ADDRINT addr, ADDRINT lastaddr, THREADID tid)
{
	ADDRINT prevaddr;
	string tnt_str;
	
	if (tid != 0) return;
	prevaddr = thr_prev_addr[tid];
	thr_prev_addr[tid] = addr;	
	// *fout << toHex4(bbl_no++) << ' ' << toHex(addr) << ' ' << BB_LAST_INS_TYPE_STR[bbl_last_ins_type[addr]] << ' ';
	*fout << toHex(addr) << ' ' << BB_LAST_INS_TYPE_STR[bbl_last_ins_type[addr]] << ' ';

	set_meblock(addr);
	
	/* 	
	BB_JMP_DIRECT, 
	BB_JMP_INDIRECT,
	BB_JCC,
	BB_CALL_DIRECT, 
	BB_CALL_INDIRECT,
	BB_RET,	
	*/
		

	if (bbl_cond_br_tgt.count(prevaddr)) {
		if (bbl_cond_br_tgt[prevaddr].first == addr) {
			*fout << '!';
#ifdef GEN_PT_PKT
			PUT_TNT_PACKET('!');
#endif
		}
		else {
			*fout << '.';
#ifdef GEN_PT_PKT
			PUT_TNT_PACKET('.');
#endif
		}
	}
	*fout << endl;

#ifdef GEN_PT_PKT
	if (bbl_has_indirect_br_tgt.count(prevaddr)) {
		PRINT_TNT_STR();
		string is_ret = "";
		if (bbl_last_ins_ret.count(prevaddr)) is_ret = "ret";
		PIN_GetLock(&lock, tid + 1);
		*fout << toHex4(packet_no++) << " tip " << toHex(addr) << ' ' << is_ret << endl;
		PIN_ReleaseLock(&lock);		
	}

	if (bbl_cond_br_tgt.count(prevaddr)) {
		if (bbl_cond_br_tgt[prevaddr].first == addr) {
			PUT_TNT_PACKET('!');
		}
		else {
			PUT_TNT_PACKET('.');
		}
	}
#endif
}


void INS_PT_WriteExecute(ADDRINT addr)
{
	set_mwblock(addr);
}

void TRC_APIOutput_Handler(ADDRINT addr, THREADID tid)
{	
	ADDRINT prevaddr = thr_prev_addr[tid];
	thr_prev_addr[tid] = addr;
	fn_info_t* fn_info = GetFunctionInfo(addr);
	if (fn_info == NULL) return;
	if (fn_info->saddr != addr) return;
	if (isMainAPITrace) {		
		if (IS_MAIN_IMG(prevaddr)) *fout << "API " << toHex(addr) << ' ' << GetAddrInfo(addr) << endl;		
	}
	else {		
		if (fn_info->saddr == addr) *fout << "# tid:" << tid << ' ' << toHex(prevaddr) << ' ' << GetAddrInfo(prevaddr) << " -> " << toHex(addr) << ' ' << GetAddrInfo(addr) << endl;		
	}
	
	//PIN_GetLock(&lock, tid + 1);
	//*fout << "# tid:" << tid << ' ' << toHex(prevaddr) << ' ' << GetAddrInfo(prevaddr) << " -> " << toHex(addr) << ' ' << GetAddrInfo(addr) << endl;
	//PIN_ReleaseLock(&lock);
		
	//fn_info_t* fn_info = GetFunctionInfo(addr);
	//if (fn_info == NULL || fn_info->name == "") return;
	//fn_info_t* prev_fn_info = GetFunctionInfo(prevaddr);
	//// if (prev_fn_info != NULL && prev_fn_info->saddr == fn_info->saddr) return;		
	//if (prev_fn_info != NULL) return;
	//PIN_GetLock(&lock, tid + 1);
	//*fout << "# tid:" << tid << ' ' << toHex(prevaddr) << ' ' << GetAddrInfo(prevaddr) << " -> " << toHex(addr) << ' ' << GetAddrInfo(addr) << endl;
	//PIN_ReleaseLock(&lock);
}

void INS_Print(CONTEXT* ctxt, ADDRINT addr, THREADID tid)
{
	PIN_GetLock(&lock, tid + 1);
	string code;
	get_disasm(addr, code);
	*fout << "I " << tid << ' ' << toHex(addr) << ' ' << code << endl;
	PIN_ReleaseLock(&lock);
}

void BBL_Skip_ExeptionHandler(CONTEXT* ctxt, ADDRINT addr, ADDRINT toaddr, THREADID tid)
{		
	ADDRINT rsp, stktop;	

	// get stack top value
	rsp = PIN_GetContextReg(ctxt, REG_STACK_PTR);	
	PIN_SafeCopy(buff, (VOID*)rsp, ADDRSIZE);
	stktop = TO_ADDRINT(buff);
	*fout << "EFLAGS:" << toHex(stktop) << endl;
	
	// get trap flag and if TF==0, do not skip
	if ((stktop & 0x100) == 0) return;

	PIN_GetLock(&lock, tid + 1);
	*fout << "# Skipping Exception handler " << tid << ' ' << toHex(addr) << "->" << toHex(toaddr) << endl;
	PIN_ReleaseLock(&lock);

	PIN_SetContextReg(ctxt, REG_STACK_PTR, rsp + ADDRSIZE);
	PIN_SetContextReg(ctxt, REG_INST_PTR, toaddr);
	PIN_ExecuteAt(ctxt);
}

void INS_HandlerExit_Handler(ADDRINT addr, THREADID tid)
{
	PIN_GetLock(&lock, tid + 1);
	*fout << "HE " << tid << ' ' << toHex(addr) << ' ' << asmcode_m[addr] << endl;
	PIN_ReleaseLock(&lock);
}


// ========================================================================================================================
// Memory Trace Functions 
// ========================================================================================================================

// shared global variable across memory read before and after
ADDRINT mem_write_addr, mem_read_addr;
stringstream delayed_msg;

void INS_Memtrace_MR(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid)
{
	// skip stack write
	if (PIN_GetContextReg(ctxt, REG_STACK_PTR) / 0x1000 == targetAddr / 0x1000) return;
	PIN_SafeCopy(buff, (VOID*)targetAddr, mSize);
	ADDRINT mem_value = buf2val(buff, mSize);
	*fout << "R " << threadid << ' ' << hexstr(ip) << ' ' << hexstr(targetAddr) << ' ' << StringHex(mem_value, mSize * 2, false) << endl;;
}


void INS_Memtrace_MW_before(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid)
{
	mem_write_addr = targetAddr;	
	delayed_msg.str("");
	delayed_msg.clear();

	// skip stack write
	if (PIN_GetContextReg(ctxt, REG_STACK_PTR) / 0x1000 == targetAddr / 0x1000) return;

	delayed_msg << "W " << threadid << ' ' << hexstr(ip) << ' ' << hexstr(targetAddr) << ' ' << mSize;
	//if (isFound) delayed_msg << " HDL";
	delayed_msg << ' ';
}

// memory trace memory write analysis function
void INS_Memtrace_MW_after(CONTEXT* ctxt, size_t mSize, THREADID threadid)
{
	if (mem_write_addr < main_img_saddr || mem_write_addr >= main_img_eaddr) return;
	// skip stack write
	if (PIN_GetContextReg(ctxt, REG_STACK_PTR) / 0x1000 == mem_write_addr / 0x1000) return;
	
	string msg = "";
	PIN_SafeCopy(buff, (VOID*)mem_write_addr, mSize);
	ADDRINT mem_value = buf2val(buff, mSize);
	delayed_msg << StringHex(mem_value, mSize * 2, false);	
	PIN_GetLock(&lock, threadid + 1);
	*fout << delayed_msg.str() << endl;
	PIN_ReleaseLock(&lock);
}


// memory trace memory write analysis function
void INS_Memtrace_MW_Handler(CONTEXT *ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack)
{
	mem_write_addr = targetAddr;
	if (is_stack && (targetAddr < main_img_saddr || targetAddr >= main_img_eaddr)) {
		return;
	}

	delayed_msg.str("");
	delayed_msg.clear();

	delayed_msg << "W " << threadid << ' ' << toHex(ip) << ' ' << toHex(targetAddr) << ' ' << mSize;
	//if (isFound) delayed_msg << " HDL";
	delayed_msg << ' ';
}

// memory trace memory write analysis function
void INS_Memtrace_MWAfter_Handler(CONTEXT *ctxt, size_t mSize, THREADID threadid, BOOL is_stack)
{
	if (is_stack && (mem_write_addr < main_img_saddr || mem_write_addr >= main_img_eaddr)) return;

	string msg = "";	
	PIN_SafeCopy(buff, (VOID*)mem_write_addr, mSize);
	ADDRINT mem_value = buf2val(buff, mSize);		

	delayed_msg << StringHex(mem_value, mSize * 2, false);
	
	ADDRINT ebp_val = PIN_GetContextReg(ctxt, REG_EBP);

	ADDRDELTA diff = mem_write_addr - ebp_val;
	if (ebp_val >= main_img_saddr && ebp_val < main_img_eaddr && diff >= 0 && diff <= 0xFF) {
		// *fout << "EBP:" << toHex(ebp_val) << " DIFF:" << toHex1(diff) << ' ';
		delayed_msg << " # EBP:" << toHex(ebp_val) << " DIFF:" << toHex1(diff) << ' ';
	}

	
	// *fout << "V:" << StringHex(mem_value, mSize * 2, false);
	
	PIN_GetLock(&lock, threadid + 1);
	*fout << delayed_msg.str() << endl;
	PIN_ReleaseLock(&lock);
}


// memory trace memory read analysis function
void INS_Memtrace_MR_Handler(CONTEXT *ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack)
{
	if (is_stack && (targetAddr < main_img_saddr || targetAddr >= main_img_eaddr)) return;

	string msg = "";
	if (hdl_addr_m.find(targetAddr) != hdl_addr_m.end()) {
		msg = " # HDL:" + toHex(hdl_addr_m[targetAddr]) + ' ';
		// msg += " EBP:" + toHex(PIN_GetContextReg(ctxt, REG_STACK_PTR));
	}

	// UINT8 buf[ADDRSIZE];	

	PIN_SafeCopy(buff, (VOID*)targetAddr, mSize);
	ADDRINT mem_value = buf2val(buff, mSize);
	ADDRINT ebp_val = PIN_GetContextReg(ctxt, REG_EBP);
	ADDRDELTA diff = targetAddr - ebp_val;

	if (ebp_val >= main_img_saddr && ebp_val < main_img_eaddr && diff >= 0 && diff <= 0xFF) {
		// msg += "\tEBP:" + toHex(ebp_val) + "\tdiff:" + toHex1(diff);
		msg += " # EBP:" + toHex(ebp_val) + " DIFF:" + toHex1(diff) + ' ';
	}

	PIN_GetLock(&lock, threadid + 1);
	*fout << "R " << threadid << ' ' << toHex(ip) << ' ' << toHex(targetAddr) << ' ' 
		<< mSize << ' ' << StringHex(mem_value, mSize * 2, false) << msg << endl;

	PIN_ReleaseLock(&lock);
}

// ========================================================================================================================
// Common Callbacks
// ========================================================================================================================

// IMG instrumentation function for EXE files
void IMG_Instrument(IMG img, void *v)
{
	string imgname = IMG_Name(img);
	size_t pos = imgname.rfind("\\") + 1;
	imgname = imgname.substr(pos);
	TO_LOWER(imgname);
	mod_info_t *modinfo = NULL;
	if (module_info_m.find(imgname) != module_info_m.end()) return;

	// Record symbol information of a loaded image 
	ADDRINT saddr = IMG_LowAddress(img);
	ADDRINT eaddr = IMG_HighAddress(img);
	modinfo = new mod_info_t(imgname, saddr, eaddr);
	module_info_m[imgname] = modinfo;
	*fout << "NAME:" << *modinfo << endl;

	if (isDLLAnalysis)
	{
		// obfuscated dll module is loaded
		if (imgname == obf_dll_name)
		{
			obf_dll_entry_addr = IMG_EntryAddress(img);
			main_img_saddr = saddr;
			main_img_eaddr = eaddr;
			main_img_info = modinfo;

			SEC sec = IMG_SecHead(img);
			main_txt_saddr = SEC_Address(sec);
			main_txt_eaddr = main_txt_saddr + SEC_Size(sec);
		}

		// loader exe file is loaded
		if (IMG_IsMainExecutable(img))
		{
			loader_saddr = saddr;
			loader_eaddr = eaddr;
		}
	}
	else
	{
		// EXE analysis
		if (IMG_IsMainExecutable(img))
		{
			main_img_saddr = saddr;
			main_img_eaddr = eaddr;

			// modify tracing start address according to memory loaded address of the executable file
			if (instrc_saddr != 0) instrc_saddr += main_img_saddr;
			if (instrc_eaddr != 0) instrc_eaddr += main_img_saddr;

			SEC sec = IMG_SecHead(img);
			main_txt_saddr = SEC_Address(sec);
			main_txt_eaddr = main_txt_saddr + SEC_Size(sec);
			
			//if (isTest) {
			//	get_exception_handler_jump_target(0x14000201C);
			//	PIN_ExitApplication(0);
			//}
		}
	}
	
	// collect symbol information
	size_t cnt = 0;	
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec), cnt++)
	{
		string secname = SEC_Name(sec);
		ADDRINT saddr = SEC_Address(sec);
		ADDRINT eaddr = saddr + SEC_Size(sec);
		sec_info_t *secinfo = new sec_info_t(imgname, secname, saddr, eaddr);
		modinfo->sec_infos.push_back(secinfo);
#if LOG_SECTION_INFO == 1
		*fout << "SECTION:" << *secinfo << endl;
#endif
		if (SEC_Name(sec) == ".text")
		{

			if (IS_MAIN_IMG(saddr))
			{
				main_txt_saddr = SEC_Address(sec);
				main_txt_eaddr = main_txt_saddr + SEC_Size(sec);
			}

			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
			{
				string rtnname = RTN_Name(rtn);
				ADDRINT saddr = RTN_Address(rtn);
				ADDRINT eaddr = saddr + RTN_Range(rtn);
				fn_info_t *fninfo = new fn_info_t(imgname, rtnname, saddr, eaddr);

				fn_info_m[saddr] = fninfo;

				module_info_m[imgname]->fn_infos.push_back(fninfo);
			}
		} 
		else if (IS_MAIN_IMG(saddr) && SEC_Name(sec) == vmsec_name)
		{
			vmsec = secinfo;
			main_vm_saddr = vmsec->saddr;
			main_vm_eaddr = vmsec->eaddr;
			*fout << "VM Section:" << *vmsec << endl;
		}
	}
}

// This routine is executed every time a thread is created.
VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	thr_prev_addr[threadid] = PIN_GetContextReg(ctxt, REG_EIP);
#if LOG_THREAD == 1
	*fout << "Starting Thread " << threadid << endl;
#endif
}

// This routine is executed every time a thread is destroyed.
VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
#if LOG_THREAD == 1
	*fout << "Ending Thread " << threadid << endl;
#endif
}

/*!
* Print out analysis results.
* This function is called when the application exits.
* @param[in]   code            exit code of the application
* @param[in]   v               value specified by the tool in the
*                              PIN_AddFiniFunction function call
*/
void Fini(INT32 code, void *v)
{
	((ofstream*)fout)->close();
}

/*!
* The main procedure of the tool.
* This function is called when the application image is loaded but not yet started.
* @param[in]   argc            total number of elements in the argv array
* @param[in]   argv            array of command line arguments,
*                              including pin -t <toolname> -- ...
*/
int main(int argc, char *argv[])
{
	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid 
	if (PIN_Init(argc, argv))
	{
		return -1;
	}


	// output file concatenates every option as a string
	string outputFileName = KnobOutputFile.Value();
	if (outputFileName == "")
	{
		outputFileName = string(argv[argc - 1]);
		for (int i = 5; i < argc - 1; i++) {
			string arg = string(argv[i]);		
			if (arg == "--") break;
			outputFileName += '_' + arg;
		}		
		outputFileName += ".txt";	
	}
	LOG(outputFileName);

	
	fout = new ofstream(outputFileName.c_str());
	
	obf_dll_name = KnobDLLFile.Value();


	string isMemTrace = KnobMemoryTrace.Value();

	if (isMemTrace == "r") isMemReadTrace = true;
	else if (isMemTrace == "w") isMemWriteTrace = true;
	else if (isMemTrace == "rw")
	{
		isMemReadTrace = true;
		isMemWriteTrace = true;
	}
	
	isInsTrace = KnobInstructionTrace.Value();
	isWriteExecute = KnobWriteExecute.Value();
	isBlockTraceHex = KnobBlockTraceHex.Value();
	isBlockTrace = KnobBlockTrace.Value();
	if (isBlockTraceHex) isBlockTrace = true;

	isAPITrace = KnobAPITrace.Value();
	isMainAPITrace = KnobMainAPITrace.Value();
	instrc_saddr = AddrintFromString(KnobTraceStartAddr.Value());
	instrc_eaddr = AddrintFromString(KnobTraceEndAddr.Value());
	string start_apis = KnobTraceStartAPIs.Value();
	
	isVMPAnalysis = KnobVMPAnalysis.Value();
	isSkipAntiPin = KnobSkipAntiDBI.Value();

	// api sequence where logging api starts
	if (start_apis != "") {
		for (size_t pos = 0, next_pos;;)
		{
			next_pos = start_apis.find(" ", pos);
			trc_start_apis.push_back(start_apis.substr(pos, next_pos));
			pos = next_pos;
			if (pos == string::npos) break;
			pos++;
		}

	}
	
	if (KnobFindHandlerAddress.Value()) analysis_step = 1;
	if (KnobVMAnalysis.Value())
	{
		isVMAnalysis = true;
	}
	vmsec_name = KnobVMSection.Value();
	
	SetAddress0x(false);

	PIN_InitSymbols();

	// Register Analysis routines to be called when a thread begins/ends
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);
	TRACE_AddInstrumentFunction(TRC_Instrument, 0);
	IMG_AddInstrumentFunction(IMG_Instrument, 0);

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
