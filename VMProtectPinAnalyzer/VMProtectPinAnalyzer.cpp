#include "VMProtectPinAnalyzer.h"
#include "Config.h"

using namespace std;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool", "o", "result.txt", "specify file name for the result");
KNOB<string> KnobDLLFile(KNOB_MODE_WRITEONCE, "pintool", "dll", "", "specify packed dll file");
KNOB<bool> KnobMemoryTrace(KNOB_MODE_WRITEONCE,  "pintool", "memtrace", "1", "specify whether to record memory trace or not");
KNOB<bool> KnobAPIDetect(KNOB_MODE_WRITEONCE,  "pintool", "apidetect", "0", "specify api detection");
KNOB<string> KnobDebug(KNOB_MODE_WRITEONCE,  "pintool", "debug", "", "specify debug output file and turn on debug mode");
KNOB<UINT32> KnobAttachDebugger(KNOB_MODE_WRITEONCE, "pintool", "attach", "0", "specify number of seconds to wait until a debugger to attach at OEP");
KNOB<string> KnobTraceStartAddr(KNOB_MODE_WRITEONCE, "pintool", "trsaddr", "0", "instruction trace start address");
KNOB<string> KnobTraceEndAddr(KNOB_MODE_WRITEONCE, "pintool", "treaddr", "0", "instruction trace end address");
KNOB<bool> KnobOEPDetect(KNOB_MODE_WRITEONCE, "pintool", "oepdetect", "0", "specify oep detection");

// ========================================================================================================================
// memory section write & execute check by block
// ========================================================================================================================

// memory write set
set<ADDRINT> mwaddrs;

#define MAX_BLOCKS 100000	// Maximum File Size : 50MB assuming that default file alignment is 512 bytes (= 0.5kB)
#define BLOCK_SIZE 512
size_t mwblocks[MAX_BLOCKS];
size_t meblocks[MAX_BLOCKS];


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
	return obf_img_saddr + blk * BLOCK_SIZE;
}

// memory write check
bool set_mwblock(ADDRINT addr)
{
	size_t idx = (addr - obf_img_saddr) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;

	// if this block is previously executed, set meblock to zero
	if (meblocks[idx] > 0) 
	{
		meblocks[idx] = 0;
		*fout << toHex(addr) << " is rewritten after execution." << endl;
	}

	// *fout << "Set MW Block " << toHex(addr) << ' ' << toHex(idx * BLOCK_SIZE + obf_img_saddr) << endl;

	mwblocks[idx]++;
	return true;
}

size_t get_mwblock(ADDRINT addr)
{
	size_t idx = (addr - obf_img_saddr) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;
	return mwblocks[idx];
}

// memory execute check
bool set_meblock(ADDRINT addr)
{
	size_t idx = (addr - obf_img_saddr) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;		
	meblocks[idx]++;
	return true;
}

size_t get_meblock(ADDRINT addr)
{
	size_t idx = (addr - obf_img_saddr) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;
	return meblocks[idx];
}


// ========================================================================================================================
// API Detection Functions 
// ========================================================================================================================


void FindAPICalls() {
	// *fout << "Find API Calls" << endl;
	
	size_t txtsize = obf_txt_eaddr - obf_txt_saddr;;
	UINT8 *buf = (UINT8*)malloc(txtsize);
	size_t idx;
	ADDRINT addr, target_addr;
	ADDRINT iat_start_addr = 0, iat_size = 0;

	unsigned char* pc = reinterpret_cast<unsigned char*>(obf_txt_saddr);

	// buf has executable memory image
	EXCEPTION_INFO *pExinfo = NULL;
	size_t numcopied = PIN_SafeCopyEx(buf, pc, txtsize, pExinfo);

	// search for address modification in program

	for (idx = 0; idx < numcopied; idx++)
	{
		// CALL r/m32 (FF 1F __ __ __ __)
		// is patched by VMProtect into
		// CALL rel32; ?? (E8 __ __ __ __ ; ??)
		if (buf[idx] == 0xE8)
		{
			addr = obf_txt_saddr + idx;
						
			
			// PATTERN 1-1: MOV reg, [e_api_fn] / ... / CALL r32 -> CALL imm32; RET or NOP / ... / CALL r32
			// -----------------------------------------------------------------
			// caller_addr-1: MOV reg, [e_api_fn]	# B8~BF ____ : 6 bytes
			// ...
			// reg_call_addr: CALL reg				# ____ : 2 bytes
			// ->
			// caller_addr-1: PUSH r32		# 50~57 1 bytes
			// caller_addr  : CALL imm32	# E8 ________ 5 bytes
			// ...
			// reg_call_addr: CALL reg		# ____ : 2 bytes
			
			
			// PATTERN 1-2: MOV reg, [e_api_fn] / ... / CALL reg -> CALL imm32; db xx (1byte) / ... / CALL reg
			// -----------------------------------------------------------------
			// caller_addr  : MOV ESI, [api_addr]	# B8~BF ____ : 6 bytes
			// ...
			// reg_call_addr: CALL reg				# FFD6 : 2 bytes
			// ->
			// caller_addr  : CALL imm32 	# E8 ________ : 5 bytes
			// caller_addr+5: db __			# __ : 1 byte
			// ...
			// reg_call_addr: CALL reg				# FFD6 : 2 bytes

			
			// PATTERN 2-1: CALL indirect -> PUSH r32; CALL imm32
			// -----------------------------------------------------------------
			// caller_addr-1: CALL imm32 # (48) FF 15 __ __ __ __	: 6 bytes or 7 bytes (with REX.W prefix when backward branch)
			// ->
			// caller_addr-1: PUSH r32		# 50~57 1 bytes
			// caller_addr  : CALL ___ # (48) E8 __ __ __ __ : 5 bytes or 6 bytes (with REX.W prefix when backward branch)		

			// PATTERN 2-2: CALL indirect -> CALL imm32; RET or NOP or INT3
			// caller_addr  : CALL ___ # (48) FF 15 __ __ __ __	: 6~7 bytes
			// ->
			// caller_addr  : CALL ___ # (48) E8 __ __ __ __ : 5~6 bytes
			// caller_addr+5: NOP or RET # 90 or C3 : 1 byte


			// PATTERN 3-1: JMP indirect -> PUSH r32; CALL imm32
			// -----------------------------------------------------------------
			// caller_addr-1: JMP ___ # (48) FF 25 __ __ __ __	: 6 bytes or 7 bytes (with REX.W prefix when backward branch)
			// ->
			// caller_addr-1: PUSH r32		# 50~57 1 bytes
			// caller_addr  : CALL ___ # (48) E8 __ __ __ __ : 5 bytes or 6 bytes (with REX.W prefix when backward branch)			

			
			// PATTERN 3-2: JMP indirect -> CALL imm32; RET or NOP
			// -----------------------------------------------------------------
			// caller_addr  : JMP ___ # (48) FF 25 __ __ __ __	: 6 bytes or 7 bytes (with REX.W prefix when backward branch)
			// ->
			// caller_addr  : CALL ___ # (48) E8 __ __ __ __ : 5 bytes or 6 bytes (with REX.W prefix when backward branch)
			// caller_addr+5: NOP or RET # 90 or C3 : 1 byte


			bool pattern_before_push_reg;
			pattern_before_push_reg = false;

			// push reg at caller_addr : PATTERN 1-1, 2-1, 3-1
			if (buf[idx - 1] >= 0x50 && buf[idx - 1] <= 0x57) {
				pattern_before_push_reg = true;
			}

			target_addr = addr + 5 + buf[idx + 1] + (buf[idx + 2] << 8) + (buf[idx + 3] << 16) + (buf[idx + 4] << 24);

			if (target_addr >= obf_txt_saddr && target_addr < obf_txt_eaddr)
			{
				continue;	// skip function call into the same section
			}
			sec_info_t *current_section = GetSectionInfo(addr);
			sec_info_t *target_section = GetSectionInfo(target_addr);

			if (current_section == NULL || target_section == NULL) continue;

			// obfuscated call target is selected by 
			// - call targets into other section of the main executables
			if (current_section->module_name == target_section->module_name &&
				current_section->saddr != target_section->saddr) {

#if LOG_CALL_CHECK == 1
				*fout << "Obfuscated Call : " << toHex(addr) << " -> " << toHex(target_addr) << endl;
#endif
				call_info_t* cinfo = new call_info_t(pattern_before_push_reg, addr, target_addr);
				// obfuscated_call_candidate_addrs.push_back(make_pair(addr, target_addr));
				obfuscated_call_candidate_addrs.push_back(cinfo);
			}
		}
	}
	free(buf);
}



// search in .rdata section
// VMProtect puts import addresses in .rdata section after unpack
// search for zero bytes of (number of api calls * 8)
bool FindGap()
{
	bool retVal = false;

	size_t size_iat = obfaddr2fn.size() * 8;

	sec_info_t *nextsection = GetNextSectionInfo(obf_rdata_saddr);

	ADDRINT gap_start_addr = obf_rdata_eaddr + 0x100 - obf_rdata_eaddr % 0x100;

	LOG(".rdata " + toHex(obf_rdata_saddr) + '\n');
	LOG("Size of IAT in bytes: " + toHex(size_iat) + '\n');
	LOG("gap start address " + toHex(gap_start_addr) + '\n');

	if (nextsection->saddr - gap_start_addr < size_iat) return false;
	
	addrZeroBlk = gap_start_addr;
	return true;
}


// Check External Reference from main image 
void CheckExportFunctions()
{

	size_t blksize = obf_txt_eaddr - addrZeroBlk;;

	map<string, fn_info_t*> sorted_api_map;
	for (auto it = obfaddr2fn.begin(); it != obfaddr2fn.end(); it++) {
		fn_info_t *fninfo = it->second;
		string key = fninfo->module_name + '.' + fninfo->name;
		sorted_api_map[key] = fninfo;
		// LOG(toHex(fninfo->saddr) + ' ' + key + "\n");
	}

	//LOG("ZERO BLOCK " + toHex(addrZeroBlk) + '\n');

	ADDRINT current_addr = addrZeroBlk;
	ADDRINT rel_addr = 0;
	size_t idx = 0;
	vector<pair<ADDRINT, fn_info_t*>> result_vec;
	for (auto it = sorted_api_map.begin(); it != sorted_api_map.end(); it++) {
		// assign resolved function address to candidate IAT area
		fn_info_t *fninfo = it->second;		
		result_vec.push_back(make_pair(current_addr - obf_img_saddr, it->second));
		current_addr += sizeof(ADDRINT);
		idx++;
	}

	// print IAT info
	*fout << "IAT START: " << toHex(addrZeroBlk - obf_img_saddr) << endl;
	*fout << "IAT SIZE: " << toHex(idx * sizeof(ADDRINT)) << endl;
	for (auto it = result_vec.begin(); it != result_vec.end(); it++) {
		*fout << toHex(it->first) << "\taddr\t" << it->second->module_name << '\t' << it->second->name << endl;
	}
}


// Find External Reference without a gap area
void FindExistingIAT()
{
	EXCEPTION_INFO *pExinfo = NULL;
	size_t img_size = obf_img_eaddr - obf_img_saddr;
	if (img_size > sizeof(memory_buffer)) {	
		*fout << "Image size too big. Please resize the buffer." << endl;
		((ofstream*)fout)->close();
		exit(0);
	}

	size_t numcopied = PIN_SafeCopyEx(memory_buffer, (VOID*)obf_img_saddr, img_size, pExinfo);

	vector<pair<size_t, ADDRINT>> IATCandidates;
	
	for (size_t i = 0; i < numcopied; i += sizeof(ADDRINT)) {		
		// check whether the value of the current address points to a API function		
		ADDRINT target = toADDRINT(memory_buffer + i);
		fn_info_t *fn = GetFunctionInfo(target);		
		if (fn != NULL) {
			IATCandidates.push_back(make_pair(i, target));
			*fout << toHex(i) << '->' << toHex(target) << endl;
		}
	}

	size_t adjacentCnt;
	ADDRINT IATStartAddr;
	
	vector<pair<size_t, size_t>> IATCandidates_selected;
	
	size_t i0, i1;
	i0 = IATCandidates.at(0).first;	
	IATStartAddr = i0;
	adjacentCnt = 1;

	for (size_t i = 1; i < IATCandidates.size(); i++) {
		i1 = IATCandidates.at(i).first;
		if (i1 - i0 > sizeof(ADDRINT) * 2) {
			// save only IAT having more than 5 function addresses
			if (adjacentCnt > 5) {
				IATCandidates_selected.push_back(make_pair(IATStartAddr, i1));				
			}
			IATStartAddr = i1;
			adjacentCnt = 1;
			continue;
		}
		adjacentCnt++;		
	}

	*fout << "Selected" << endl;
	for (auto i : IATCandidates_selected) {
		*fout << toHex(i.first) << ' ' << toHex(i.second - i.first) << endl;
	}
	*fout << endl;

	//// print IAT info
	//*fout << "IAT START: " << toHex(addrZeroBlk - obf_img_saddr) << endl;
	//*fout << "IAT SIZE: " << toHex(idx * sizeof(ADDRINT)) << endl;
	//for (auto it = result_vec.begin(); it != result_vec.end(); it++) {
	//	*fout << toHex(it->first) << "\taddr\t" << it->second->module_name << '\t' << it->second->name << endl;
	//}
}


// API detect analysis function
void TRC_APIDetect_analysis(CONTEXT *ctxt, ADDRINT addr, UINT32 size, THREADID threadid)
{
	if (threadid != 0) return;
	// if (oep) *fout << toHex(addr) << endl;

	if (isCheckAPIRunning) {

		ADDRINT caller_addr = current_obfuscated_call->caller_addr;
		ADDRINT prev_addr = 0;
		if (!traceAddrSeq.empty())
		{
			prev_addr = *traceAddrSeq.rbegin();
		}
		fn_info_t *fninfo = GetFunctionInfo(addr);
		ADDRINT stkptr = PIN_GetContextReg(ctxt, REG_STACK_PTR);
		
		traceAddrSeq.push_back(addr);
		traceSPSeq.push_back(stkptr);

		for (auto ins_addr : *trace_cache_m[addr])
		{
			string asmcode = asmcode_m[ins_addr];
			
			// if abnormal instruction, leave
			if (check_abnormal_ins(asmcode))
			{
				isCheckAPIStart = true;
				isCheckAPIRunning = false;
				goto check_api_start;
			}			
		}
		
#if LOG_CALL_CHECK == 1
		*fout << "Checking : " << GetAddrInfo(addr) << " ESP:" << toHex(stkptr) << " T:" << toHex(addr) << endl;
		for (auto ins_addr : *trace_cache_m[addr])
		{
			*fout << toHex(ins_addr) << ' ' << asmcode_m[ins_addr] << endl;
		}
#endif


		// .text:     ...
		//   mov_obf_caller: call mov_obf_addr
		//                   db xx
		//   ret_addr      : ... 
		//                   ...
		//   obf_caller    : call REG 
		// 
		// .vmp0:             
		//                    ...
		//   mov_obf_addr  :  ...
		//                    ... (the effect of obfuscated code is equivalent to MOV REG, api_fn )
		//                    ret xx
		

		// check MOV reg, api_fn
		if (addr == caller_addr + 5 || addr == caller_addr + 6)
		{
			// check 'mov reg, [iat:api_function]'
			REG set_api_reg = check_api_fn_assignment_to_register(ctxt);			
			if (set_api_reg != REG_NONE)
			{				
				ADDRINT trc_last_ins_addr = *trace_cache_m[prev_addr]->rbegin();
#if LOG_CALL_CHECK == 1
				*fout << "MOV Caller address: " << toHex(caller_addr) << endl;
				*fout << "MOV return address: " << toHex(addr) << endl;
				*fout << "MOV next to Caller address: " << toHex(trace_next_addr_m[caller_addr]) << endl;
				*fout << "SP before mov call: " << toHex(traceSPSeq[0]) << endl;
				*fout << "SP after mov call : " << toHex(stkptr) << endl;
#endif
				ADDRINT adjusted_caller_addr = addr - 6;
				ADDRINT api_fn_addr = movRegApiFnAddrs[set_api_reg].first;
				fninfo = GetFunctionInfo(api_fn_addr);
				*fout << toHex(adjusted_caller_addr - obf_img_saddr) << "\tmov\t" << fninfo->module_name << '\t' << fninfo->name << endl;
				obfaddr2fn[current_obf_fn_addr] = fninfo;
			}
			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			goto check_api_start;						
		}

		// skip obfuscated code
		if (addr >= obf_txt_eaddr && addr < obf_img_eaddr)
		{
			return;
		}

		// if the trace not in in API function, skip
		if (fninfo == NULL) return;

		// skip user exception by false positive find api calls
		if (fninfo->name.find("KiUserExceptionDispatcher") != string::npos)
		{
			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			goto check_api_start;
		}

		// Check call/jmp
		// Compare stack top to check the return address which points to the next to the caller instruction. 		
		PIN_SafeCopy((VOID*)memory_buffer, (VOID*)stkptr, sizeof(ADDRINT));
		ADDRINT stk_top_value = toADDRINT(memory_buffer);
		ADDRINT original_addr;		
		ADDRINT adjusted_caller_addr;		
		string call_type;

		INT32 stk_diff = traceSPSeq[0] - stkptr;
		if (stk_diff != 0 && stk_diff != sizeof(ADDRINT) && stk_diff != -sizeof(ADDRINT))
		{
			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			goto check_api_start;
		}
		
		original_addr = caller_addr;

		if (stk_top_value == caller_addr + 5 || stk_top_value == caller_addr + 6) {				
			call_type = "call";
			if (stk_diff == sizeof(ADDRINT))
			{
				adjusted_caller_addr = caller_addr;
			}
			else if (stk_diff == 0)
			{
				adjusted_caller_addr = caller_addr - 1;
			}
			else
			{
				isCheckAPIStart = true;
				isCheckAPIRunning = false;
				goto check_api_start;
			}
		}		
		else
		{
			call_type = "goto";		
			if (stk_diff == 0)
			{				
				adjusted_caller_addr = caller_addr;	
			}
			else if (stk_diff == -sizeof(ADDRINT))
			{
				adjusted_caller_addr = caller_addr - 1;
			}
			else
			{
				isCheckAPIStart = true;
				isCheckAPIRunning = false;
				goto check_api_start;
			}
		}

#if LOG_CALL_CHECK == 1
		*fout << "Caller address: " << toHex(caller_addr) << endl;
		*fout << "return address: " << toHex(stk_top_value) << endl;
		*fout << "next to Caller address: " << toHex(trace_next_addr_m[caller_addr]) << endl;
		*fout << "SP before call: " << toHex(traceSPSeq[0]) << endl;
		*fout << "SP at API function: " << toHex(stkptr) << endl;
		*fout << "call type: " << call_type << endl;
#endif

		*fout << toHex(adjusted_caller_addr - obf_img_saddr) << '\t' << call_type << '\t' << fninfo->module_name << '\t' << fninfo->name << endl;
		obfaddr2fn[current_obf_fn_addr] = fninfo;

		isCheckAPIStart = true;
		isCheckAPIRunning = false;
		goto check_api_start;
	}

check_api_start:
	// For each obfuscated call instruction,
	// check whether the execution trace go into API function.
	// Therefore IP is changed into obfuscated function call one by one
	if (isCheckAPIStart) {
		restore_regs(ctxt);

		if (current_obf_fn_pos == obfuscated_call_candidate_addrs.size()) {
			// when checking obfuscated call finished, prepare the end 
			isCheckAPIStart = false;
			isCheckAPIEnd = true;
#if LOG_CALL_CHECK == 1
			*fout << "Checking End " << current_obf_fn_pos << endl;
#endif

			goto check_api_end;
		}
		call_info_t *callinfo = obfuscated_call_candidate_addrs.at(current_obf_fn_pos++);
#if LOG_CALL_CHECK == 1
		*fout << "Checking : " << toHex(callinfo->caller_addr) << ' ' << current_obf_fn_pos << '/' << obfuscated_call_candidate_addrs.size() << endl;				
#endif
		traceAddrSeq.clear();
		traceSPSeq.clear();
		movRegApiFnAddrs.clear();
		
		// currently call instruction is of the form 'E8 __ __ __ __' which is 5 bytes
		// but originally it is 'FF 15 __ __ __ __' or 'FF 25 __ __ __ __' which is 6 bytes
		// we need to adjust caller address

		current_obfuscated_call = callinfo;		

		isCheckAPIStart = false;
		isCheckAPIRunning = true;
		isMovRegCallReg = false;

		current_obf_fn_addr = callinfo->target_addr;
		
		PIN_SetContextReg(ctxt, REG_INST_PTR, callinfo->caller_addr);
		PIN_ExecuteAt(ctxt);		
	}

check_api_end:
	if (isCheckAPIEnd) {
		// after checking obfuscated calls, terminate.
		// *fout << "end" << endl;
		if (FindGap()) {
#if LOG_CALL_CHECK == 1
			*fout << "Searching for IAT" << endl;
#endif
			CheckExportFunctions();
		}
		else {
#if LOG_CALL_CHECK == 1
			*fout << "Searching for IAT" << endl;
#endif
			FindExistingIAT();
		}
		((ofstream*)fout)->close();
		PIN_ExitProcess(-1);
	}
	prevaddr = addr;
}

void restore_regs(LEVEL_VM::CONTEXT * ctxt)
{
	for (REG reg : regs_for_obfuscation) {
		PIN_SetContextReg(ctxt, reg, (ADDRINT)reg);
	}
}

REG check_api_fn_assignment_to_register(LEVEL_VM::CONTEXT * ctxt)
{
	REG set_api_reg = REG_NONE;
	for (REG reg : regs_for_obfuscation) {
		ADDRINT reg_val = PIN_GetContextReg(ctxt, reg);
		fn_info_t *fn = GetFunctionInfo(reg_val);
		*fout << "MOV " << REG_StringShort(reg) << ", " << toHex(reg_val) << ' ';
		if (fn)
		{			
			set_api_reg = reg;
			movRegApiFnAddrs[reg] = make_pair(reg_val, fn->detailed_name());
			*fout << fn->detailed_name();
		}
		*fout << endl;		
	}	
	return set_api_reg;
}

REG check_reg_call_ins(std::string &disasm)
{
	if (disasm.find("call") != string::npos)
	{
#ifdef TARGET_IA32
		if (disasm.find("eax") != string::npos) return REG_EAX;
		else if (disasm.find("ebx") != string::npos) return REG_EBX;
		else if (disasm.find("ecx")!= string::npos) return REG_ECX;
		else if (disasm.find("edx")!= string::npos) return REG_EDX;
		else if (disasm.find("esi")!= string::npos) return REG_ESI;
		else if (disasm.find("edi")!= string::npos) return REG_EDI;
#elif TARGET_IA32E
		if (disasm.find("rax")!= string::npos) return REG_RAX;
		else if (disasm.find("rbx") != 0) return REG_RBX;
		else if (disasm.find("rcx") != 0) return REG_RCX;
		else if (disasm.find("rdx") != 0) return REG_RDX;
		else if (disasm.find("rsi") != 0) return REG_RSI;
		else if (disasm.find("rdi") != 0) return REG_RDI;
#endif		
	}
	return REG_NONE;
}

bool check_abnormal_ins(std::string & disasm)
{
	string abnormal_ins_set[] = { "leave", "in", "out", "far", "hlt", "mov esp"};
	for (auto ins : abnormal_ins_set)
	{
		if (disasm.find(ins) != string::npos) return true;
	}	
	return false;
}

// EXE trace instrumentation function
void EXE_TRC_APIDetect_inst(TRACE trace, void *v)
{
	ADDRINT addr = TRACE_Address(trace);
	
	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)TRC_APIDetect_analysis,
		IARG_CONTEXT,
		IARG_ADDRINT, addr,
		IARG_UINT32, TRACE_Size(trace), 
		IARG_THREAD_ID,
		IARG_END);

	trace_cache_m[addr] = new vector<ADDRINT>;
	trace_next_addr_m[addr] = addr + TRACE_Size(trace);

	// instrument each memory read/write instruction	
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			ADDRINT insaddr = INS_Address(ins);
			asmcode_m[insaddr] = INS_Disassemble(ins);			
			trace_cache_m[addr]->push_back(insaddr);

			if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins))
			{
				// *fout << "MWC:" << toHex(insaddr) << ' ' << asmcode_m[insaddr] << endl;
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)INS_APIDetect_MW_analysis,
					IARG_MEMORYWRITE_EA,
					IARG_ADDRINT, insaddr, 
					IARG_END);
			}
		}
	}

	if (addr >= obf_txt_saddr && addr < obf_txt_eaddr)
	{

		if (isDebug) *fout << ".text exe:" << toHex(addr) << ' ' << asmcode_m[addr] << endl;

		// find OEP and then near OEP
		// Debugger stops when HWBP is set on OEP
		// but HWBP on near OEP works well
		if (oep == 0) {
			// *fout << "OEP" << endl;
			set_meblock(addr);
			if (get_mwblock(addr) && get_meblock(addr) == 1)
			{
				
				BBL bbl = TRACE_BblHead(trace);
				INS ins = BBL_InsHead(bbl);

				// *fout << "OEP candidates:" << toHex(addr) << ' ';
				// *fout << INS_Disassemble(ins) << ' ' << INS_IsRet(ins) << ' ' << INS_IsCall(ins) << endl;
				if (!INS_IsRet(ins) /* && !INS_IsCall(ins)*/ ) {
					oep = addr;
					*fout << "OEP:" << toHex(oep - obf_img_saddr) << endl;
					FindAPICalls();					
					isCheckAPIStart = true;
				}				
			} 
		}
	}
}

// EXE INS memory write analysis function 
void INS_APIDetect_MW_analysis(ADDRINT targetAddr, ADDRINT insaddr)
{	
	// *fout << "MW:" << toHex(insaddr) << "->" << toHex(targetAddr) << endl;
	set_mwblock(targetAddr);	
}

// ========================================================================================================================
// Memory Trace Functions 
// ========================================================================================================================

// memory trace analysis function
void EXE_TRC_Memtrc_analysis(ADDRINT addr, THREADID threadid)
{
	mod_info_t *minfo = GetModuleInfo(addr);	
	mod_info_t *prevminfo = prevmod;
	prevmod = minfo;
	if (minfo == NULL) return;
	if (minfo->isDLL() && prevminfo != NULL && prevminfo->isDLL()) return;

	PIN_GetLock(&lock, threadid+1);
	if (isDebug) *fout << toHex(addr) << ' ' << "T:" << threadid << " " << GetAddrInfo(addr) << endl;
	PIN_ReleaseLock(&lock);	
}

// memory trace instrumentation function
void EXE_TRC_MemTrace_inst(TRACE trace, void *v)
{
	ADDRINT addr = TRACE_Address(trace);

#if RECORDTRACE == 1
	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)EXE_TRC_Memtrc_analysis,
		IARG_ADDRINT, addr,
		IARG_THREAD_ID,
		IARG_END);
#endif

	// skip dll module
	mod_info_t *minfo = GetModuleInfo(addr);
	if (minfo == NULL || minfo->isDLL()) return;

	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{

			// for efficiency exclude cmp and scasb instructions
			if (INS_Opcode(ins) == XED_ICLASS_CMP ||
				INS_Opcode(ins) == XED_ICLASS_SCASB ||
				INS_Opcode(ins) == XED_ICLASS_SCASW ||
				INS_Opcode(ins) == XED_ICLASS_SCASD) continue;

			ADDRINT addr = INS_Address(ins);
			asmcode_m[addr] = INS_Disassemble(ins);

			if (INS_IsMemoryRead(ins) && !INS_IsStackRead(ins))
			{
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)EXE_INS_Memtrace_MR_analysis,
					IARG_INST_PTR,
					IARG_MEMORYREAD_SIZE,
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			}

			if (INS_HasMemoryRead2(ins) && !INS_IsStackRead(ins))
			{
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)EXE_INS_Memtrace_MR_analysis,
					IARG_INST_PTR,
					IARG_MEMORYREAD_SIZE,
					IARG_MEMORYREAD2_EA,
					IARG_THREAD_ID,
					IARG_END);
			}

			if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins))
			{
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)EXE_INS_Memtrace_MW_analysis,
					IARG_INST_PTR,
					IARG_MEMORYWRITE_SIZE,
					IARG_MEMORYWRITE_EA,
					IARG_THREAD_ID,
					IARG_END);
			}
		}
	}
}

// memory trace memory write analysis function
void EXE_INS_Memtrace_MW_analysis(ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid)
{
	if (ip >= obf_rdata_saddr && ip < obf_rdata_eaddr) {
		PIN_GetLock(&lock, threadid + 1);
		*fout << toHex(ip) << " W:" << toHex(targetAddr) << " " << mSize << ' ' << GetAddrInfo(targetAddr) << ' ' << asmcode_m[ip] << endl;
		PIN_ReleaseLock(&lock);
	}	
}

// memory trace memory read analysis function
void EXE_INS_Memtrace_MR_analysis(ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid)
{
	if (ip >= obf_rdata_saddr && ip < obf_rdata_eaddr) {
		PIN_GetLock(&lock, threadid + 1);
		*fout << toHex(ip) << " R:" << toHex(targetAddr) << " " << mSize << ' ' << GetAddrInfo(targetAddr) << ' ' << asmcode_m[ip] << endl;
		PIN_ReleaseLock(&lock);
	}
}



// ========================================================================================================================
// Instruction Trace Functions 
// ========================================================================================================================

// Instruction trace analysis function for executables
void EXE_TRC_InsTrc_Analysis(ADDRINT ip, THREADID threadid)
{
	if (threadid != 0) return;
	if (isInsTrcReady) {
		mod_info_t *modinfo = GetModuleInfo(ip);

		ADDRINT baseaddr = 0;
		if (modinfo != NULL) baseaddr = modinfo->saddr;
		for (auto it = trace_cache_m[ip]->begin(); it != trace_cache_m[ip]->end(); it++) {
			ADDRINT addr = *it;
			if (addr == instrc_saddr) isInsTrcOn = true;
			if (!isInsTrcOn) continue;

			if (baseaddr != 0) {
				*fout << modinfo->name << '+' << toHex(addr - baseaddr) << ' ' << asmcode_m[addr] << endl;
			}
			else {
				*fout << toHex(addr) << ' ' << asmcode_m[addr] << endl;
			}
							
			if (addr == instrc_eaddr) {
				isInsTrcReady = false;
				isInsTrcOn = false;
				return;
			}
		}	
	}
}

// Trace instrumentation function for executable file instruction trace
void EXE_TRC_InsTrc_Inst(TRACE trace, void *v)
{
	ADDRINT addr = TRACE_Address(trace);

	// check approximately by memory block
	if (addr / 0x1000 == instrc_saddr / 0x1000) isInsTrcWatchOn = true;
	if (!isInsTrcWatchOn) return;

	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)EXE_TRC_InsTrc_Analysis,
		IARG_ADDRINT, addr,
		IARG_THREAD_ID,
		IARG_END);

	trace_cache_m[addr] = new vector<ADDRINT>;

	// skip dll module
	mod_info_t *minfo = GetModuleInfo(addr);
	
	// if (minfo == NULL || minfo->isDLL()) return;

	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			ADDRINT insaddr = INS_Address(ins);
			if (insaddr == instrc_saddr) isInsTrcReady = true;
			asmcode_m[insaddr] = INS_Disassemble(ins);
			trace_cache_m[addr]->push_back(insaddr);
		}
	}
}


// ========================================================================================================================
// Thread Instrumentation
// ========================================================================================================================

// This routine is executed every time a thread is created.
VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	thr_cnt++;
	if (isDebug) *dout << "Starting Thread " << threadid << endl;
	thread_ids.insert(threadid);
	if (threadid == 0)
	{
		mainThreadUid = PIN_ThreadUid();
	}
}

// This routine is executed every time a thread is destroyed.
VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	thr_cnt--;
	if (isDebug) *dout << "Ending Thread " << threadid << endl;
	thread_ids.erase(threadid);
}



// ========================================================================================================================
// Executable Image Instrumentation
// ========================================================================================================================

// IMG instrumentation function for EXE files
void EXE_IMG_inst(IMG img, void *v)
{
	string imgname = IMG_Name(img);
	TO_LOWER(imgname);
	size_t pos = imgname.rfind("\\") + 1;
	imgname = imgname.substr(pos);
	
	if (module_info_m.find(imgname) != module_info_m.end()) return;

	string name = imgname;
	ADDRINT saddr = IMG_LowAddress(img);
	ADDRINT eaddr = IMG_HighAddress(img);

	mod_info_t *modinfo = modinfo = new mod_info_t(name, saddr, eaddr);
	module_info_m[name] = modinfo;

	// if this image is a dll loader
	if (isDLLAnalysis && IMG_IsMainExecutable(img))
	{
		// loader
		loader_saddr = saddr;
		loader_eaddr = eaddr;
	}

	// dll or exe to deobfuscated
	bool is_obfuscated_img = false;

	if (imgname == dll_name || !isDLLAnalysis && IMG_IsMainExecutable(img))
	{		
		obf_img_saddr = saddr;
		obf_img_eaddr = eaddr;
		obf_entry_addr = IMG_Entry(img);

		// modify tracing start address according to memory loaded address of the executable file
		if (instrc_saddr != 0) instrc_saddr += obf_img_saddr;
		if (instrc_eaddr != 0) instrc_eaddr += obf_img_saddr;

		SEC sec = IMG_SecHead(img);
		obf_txt_saddr = SEC_Address(sec);
		obf_txt_eaddr = obf_txt_saddr + SEC_Size(sec);
	}
	
#if LOG_IMAGE_INFO == 1
		*fout << name << '\t' << toHex(saddr) << "," << toHex(eaddr) << endl;
#endif

	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		string secname = SEC_Name(sec);
		ADDRINT saddr = SEC_Address(sec);
		ADDRINT eaddr = saddr + SEC_Size(sec);
		sec_info_t *secinfo = new sec_info_t(imgname, secname, saddr, eaddr);
		modinfo->sec_infos.push_back(secinfo);		
				
#if LOG_SECTION_INFO == 1
		*fout << '\t' << secname << '\t' << toHex(saddr) << "," << toHex(eaddr) << endl;
#endif

		if (SEC_Name(sec) == ".text")
		{

			if (IMG_IsMainExecutable(img))
			{
				obf_txt_saddr = SEC_Address(sec);
				obf_txt_eaddr = obf_txt_saddr + SEC_Size(sec);
			}

			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
			{
				string rtnname = RTN_Name(rtn);
				ADDRINT saddr = RTN_Address(rtn);
				ADDRINT eaddr = saddr + RTN_Range(rtn);
				fn_info_t *fninfo = new fn_info_t(imgname, rtnname, saddr, eaddr);

				fn_info_m[saddr] = fninfo;
				fn_str_2_fn_info[make_pair(imgname, rtnname)] = fninfo;
				module_info_m[imgname]->fn_infos.push_back(fninfo);
			}
		}
		else if (SEC_Name(sec) == ".rdata" && IMG_IsMainExecutable(img)) {
			obf_rdata_saddr = SEC_Address(sec);
			obf_rdata_eaddr = obf_rdata_saddr + SEC_Size(sec);
		}
	}
}

// IMG instrumentation function for DLL files
void DLL_IMG_inst(IMG img, void *v)
{
	string imgname = IMG_Name(img);
	TO_LOWER(imgname);	
	size_t pos = imgname.rfind("\\") + 1;
	imgname = imgname.substr(pos);

	ADDRINT module_addr = IMG_Entry(img);

	if (imgname == dll_name)
	{
		obf_entry_addr = module_addr;
		if (isDebug) *fout << "DLL Entry Address: " << toHex(obf_entry_addr) << endl;
	}

	mod_info_t *dllinfo = NULL;

	if (module_info_m.find(imgname) != module_info_m.end()) return;

	// Record symbol information of a loaded image 
	string name = imgname;
	ADDRINT saddr = IMG_LowAddress(img);
	ADDRINT eaddr = IMG_HighAddress(img);

	if (IMG_IsMainExecutable(img))
	{
		loader_saddr = saddr;
		loader_eaddr = eaddr;
	}

	if (imgname == dll_name)
	{
		obf_img_saddr = saddr;
		obf_img_eaddr = eaddr;

		// modify tracing start address according to memory loaded address of the executable file
		if (instrc_saddr != 0) instrc_saddr += obf_img_saddr;
		if (instrc_eaddr != 0) instrc_eaddr += obf_img_saddr;

	}

	dllinfo = new mod_info_t(name, saddr, eaddr);
	module_info_m[name] = dllinfo;

	if (isDebug) *fout << "Module: " << *dllinfo << endl;
	
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		string secname = SEC_Name(sec);
		ADDRINT saddr = SEC_Address(sec);
		ADDRINT eaddr = saddr + SEC_Size(sec);
		sec_info_t *secinfo = new sec_info_t(imgname, secname, saddr, eaddr);
		dllinfo->sec_infos.push_back(secinfo);
		if (isDebug) *fout << "    Section: " << *secinfo << endl;

		if (SEC_Name(sec) == ".text")
		{
			if (imgname == dll_name)
			{
				obf_txt_saddr = SEC_Address(sec);
				obf_txt_eaddr = obf_txt_saddr + SEC_Size(sec);
			}

			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
			{
				string rtnname = RTN_Name(rtn);
				ADDRINT saddr = RTN_Address(rtn);
				ADDRINT eaddr = saddr + RTN_Range(rtn);
				fn_info_t *fninfo = new fn_info_t(imgname, rtnname, saddr, eaddr);
				fn_info_m[saddr] = fninfo;
				fn_str_2_fn_info[make_pair(imgname, rtnname)] = fninfo;
				module_info_m[imgname]->fn_infos.push_back(fninfo);
			}
		}
		else if (SEC_Name(sec) == ".rdata" && imgname == dll_name) {
			obf_rdata_saddr = SEC_Address(sec);
			obf_rdata_eaddr = obf_rdata_saddr + SEC_Size(sec);
		}

	}
}

// ========================================================================================================================
// DLL Instrumentation
// ========================================================================================================================

// TRACE instrumentation function for DLL files
void DLL_TRC_APIDetectinst(TRACE trace, void *v)
{
	ADDRINT addr = TRACE_Address(trace);
	
	// *fout << toHex(addr) << endl;
	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)TRC_APIDetect_analysis,
		IARG_CONTEXT,
		IARG_ADDRINT, addr,
		IARG_UINT32, TRACE_Size(trace), 
		IARG_THREAD_ID,
		IARG_END);

	if (addr == obf_entry_addr) {
		is_unpack_started = true;
		LOG("unpack started");
	}

	if (is_unpack_started && addr >= loader_saddr && addr < loader_eaddr)
	{
		LOG("unpack ended");
		FindAPICalls();
		isCheckAPIStart = true;
	}
}

//////////////////////////////////////////////////////////
// OEP Detect Function
//////////////////////////////////////////////////////////
void EXE_TRC_OEPDetect_inst(TRACE trace, void *v) {
	ADDRINT addr = TRACE_Address(trace);
	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)EXE_TRC_OEPDetect_analysis,
		IARG_ADDRINT, addr,
		IARG_THREAD_ID,
		IARG_END);

	// instrument each memory write instruction
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			// if (INS_Mnemonic(ins) == "XRSTOR") continue;

			if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins))
			{
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)EXE_INS_OEPDetect_MW_analysis,
					IARG_CONTEXT,
					IARG_INST_PTR,
					IARG_UINT32, INS_Address(ins) + INS_Size(ins),
					IARG_MEMORYWRITE_SIZE,
					IARG_MEMORYWRITE_EA,
					IARG_THREAD_ID,
					IARG_END);
			}
		}
	}

	if (addr >= obf_txt_saddr && addr < obf_txt_eaddr)
	{
		// find OEP and then near OEP
		// Debugger stops when HWBP is set on OEP
		// but HWBP on near OEP works well
		if (oep == 0) {
			set_meblock(addr);
			if (get_mwblock(addr) && get_meblock(addr) == 1)
			{
				oep = addr;
				*fout << "OEP:" << toHex(oep - obf_img_saddr) << endl;
			}
		}
		// near OEP is the address of the first call instruction 
		else {
			for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
				for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
					ADDRINT taddr = INS_Address(ins);
					if (taddr < obf_txt_saddr || taddr > obf_txt_eaddr) continue;
					if (INS_IsCall(ins)) {
						// oep = INS_Address(ins);
						oep = BBL_Address(bbl);
						*fout << "NEAR OEP:" << toHex(oep - obf_img_saddr) << endl;
						((ofstream*)fout)->close();
						if (debugger_attach_wait_time) isDetach = true;
						else PIN_ExitProcess(-1);
						return;
					}
				}
			}
		}
		return;
	}

}

void EXE_TRC_OEPDetect_analysis(ADDRINT addr, THREADID threadid) {
	if (threadid != 0) return;

	if (threadid == 0)
	{
		fn_info_t *info1 = GetFunctionInfo(addr);
		fn_info_t *info2 = GetFunctionInfo(prevaddr);
		if (info1 != NULL && info2 != NULL &&
			prevaddr >= obf_img_saddr && prevaddr < obf_img_eaddr &&
			(addr > obf_img_eaddr || addr < obf_img_saddr))
		{
			*fout << "call : " << info1->name << endl;
		}

	}
	prevaddr = addr;
}


void EXE_INS_OEPDetect_MW_analysis(CONTEXT *ctxt, ADDRINT ip, ADDRINT nextip, size_t mSize, ADDRINT targetAddr, THREADID threadid) {
	set_mwblock(targetAddr);
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
	*fout << isCheckAPIStart << endl;
	*fout << isCheckAPIRunning << endl;

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
    if( PIN_Init(argc,argv) )
    {
        return -1;
    }
	
	xed_tables_init();

	string outputFileName = KnobOutputFile.Value();	
	//if (outputFileName == "result.txt")
	//{		
	//	outputFileName = string(argv[argc - 1]);
	//	outputFileName += ".txt";
	//}	
	
	fout = new ofstream(outputFileName.c_str());	

	isMemTrace = KnobMemoryTrace.Value();
	isAPIDetect = KnobAPIDetect.Value();
	isOEPDetect = KnobOEPDetect.Value();

	string debugFileName = KnobDebug.Value();	    
	dout = new ofstream(debugFileName.c_str());

	if (debugFileName != "") isDebug = true;

	dll_name = KnobDLLFile.Value();
	if (dll_name != "") {
		isDLLAnalysis = true;

		*fout << "TYPE:DLL" << endl;
		*fout << "NAME:" << dll_name << endl;

		TO_LOWER(dll_name);
		size_t pos = dll_name.rfind("\\");	
		if (pos != string::npos) dll_name = dll_name.substr(pos + 1);
		
	}
	else {		
		*fout << "TYPE:EXE" << endl;
	}

	debugger_attach_wait_time = KnobAttachDebugger.Value() * 1000;
	
	instrc_saddr = AddrintFromString(KnobTraceStartAddr.Value());
	// *fout << toHex(instrc_saddr) << endl;
	instrc_eaddr = AddrintFromString(KnobTraceEndAddr.Value());

	PIN_InitSymbols();

	// Register Analysis routines to be called when a thread begins/ends
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	// Register function to be called to instrument traces
	IMG_AddInstrumentFunction(EXE_IMG_inst, 0);
	if (isDLLAnalysis) {
		if (isAPIDetect) TRACE_AddInstrumentFunction(DLL_TRC_APIDetectinst, 0);			
		if (instrc_saddr != 0) TRACE_AddInstrumentFunction(EXE_TRC_InsTrc_Inst, 0);

		// IMG_AddInstrumentFunction(DLL_IMG_inst, 0);
	}
	else {

		if (isMemTrace) TRACE_AddInstrumentFunction(EXE_TRC_MemTrace_inst, 0);

		if (isAPIDetect) {
			TRACE_AddInstrumentFunction(EXE_TRC_APIDetect_inst, 0);
		}

		if (isOEPDetect) {
			TRACE_AddInstrumentFunction(EXE_TRC_OEPDetect_inst, 0);
		}

		if (instrc_saddr != 0) {
			TRACE_AddInstrumentFunction(EXE_TRC_InsTrc_Inst, 0);
		}

		// IMG_AddInstrumentFunction(EXE_IMG_inst, 0);
	}

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
