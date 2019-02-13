#include "VMProtectPinAnalyzer.h"
#include "Config.h"

using namespace std;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool", "o", "result.txt", "specify file name for the result");
KNOB<string> KnobDLLFile(KNOB_MODE_WRITEONCE, "pintool", "dll", "", "specify packed dll file");
KNOB<BOOL> KnobDirectCall(KNOB_MODE_WRITEONCE, "pintool", "direct", "", "direct call");


// ========================================================================================================================
// memory section write & execute check by block
// ========================================================================================================================

// memory write set
set<ADDRINT> mwaddrs;

#define MAX_BLOCKS 100000	// Maximum File Size : 50MB assuming that default file alignment is 512 bytes (= 0.5kB)
#define BLOCK_SIZE 512
size_t mwblocks[MAX_BLOCKS];
size_t meblocks[MAX_BLOCKS];

#define LOG_CALL_CHECK 1

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
		*fout << toHex(addr) << " is rewritten after execution." << endl;
	}

	// *fout << "Set MW Block " << toHex(addr) << ' ' << toHex(idx * BLOCK_SIZE + obf_img_saddr) << endl;

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


// ========================================================================================================================
// API Detection Functions 
// ========================================================================================================================


void FindObfuscatedAPICalls() {	
	isFoundAPICalls = true;
#if LOG_CALL_CHECK == 1
	*fout << "# Find API Calls" << endl;
#endif
	size_t txtsize = main_txt_eaddr - main_txt_saddr;;
	UINT8 *buf = (UINT8*)malloc(txtsize);
	size_t idx;
	ADDRINT addr, target_addr;
	ADDRINT iat_start_addr = 0, iat_size = 0;

	unsigned char* pc = reinterpret_cast<unsigned char*>(main_txt_saddr);

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
			addr = main_txt_saddr + idx;
						
			
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

			if (target_addr >= main_txt_saddr && target_addr < main_txt_eaddr)
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
				*fout << "# Obfuscated Call : " << toHex(addr) << " -> " << toHex(target_addr) << endl;
#endif
				call_info_t* cinfo = new call_info_t(pattern_before_push_reg, addr, target_addr);
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

	size_t size_iat = (isDirectCall?mov_obfaddr2fn.size():obfaddr2fn.size()) * ADDRSIZE;

	sec_info_t *nextsection = GetNextSectionInfo(obf_rdata_saddr);

	ADDRINT gap_start_addr;	// obf_rdata_eaddr - 0x100 - obf_rdata_eaddr % 0x100;
	gap_start_addr = obf_rdata_saddr;

	LOG("number of mov_direct:" + toHex(mov_obfaddr2fn.size()) + '\n');
	LOG(".rdata " + toHex(obf_rdata_saddr) + '\n');
	LOG("next section saddr: " + toHex(nextsection->saddr) + '\n');
	LOG("Size of IAT in bytes: " + toHex(size_iat) + '\n');
	LOG("gap start address " + toHex(gap_start_addr) + '\n');

	// addrZeroBlk = gap_start_addr;
	imp_start_addr = obf_rdata_saddr;

	EXCEPTION_INFO *pExinfo = NULL;
	size_t numcopied = PIN_SafeCopyEx(memory_buffer, (VOID*)obf_rdata_saddr, obf_rdata_eaddr - obf_rdata_saddr, pExinfo);

	for (ADDRINT addr = obf_rdata_saddr; addr < obf_rdata_eaddr; addr += ADDRSIZE) {			
		ADDRINT val = TO_ADDRINT(memory_buffer + addr - obf_rdata_saddr);
		if (GetAddrInfo(val) == "") {
			// insert RVA of function slot
			function_slots_in_rdata.push_back(addr - main_img_saddr);
		}
	}
	
	if (nextsection->saddr - gap_start_addr < size_iat) return false;
	
	return true;
}


// Check External Reference from main image 
void CheckExportFunctions()
{

	size_t blksize = main_txt_eaddr - imp_start_addr;;

	map<string, fn_info_t*> sorted_api_map;
	for (auto it: (isDirectCall?mov_obfaddr2fn:obfaddr2fn)) {	
		fn_info_t *fninfo = it.second;
		string key = fninfo->module_name + '.' + fninfo->name;
		sorted_api_map[key] = fninfo;
		// LOG(toHex(fninfo->saddr) + ' ' + key + "\n");
	}

	//LOG("ZERO BLOCK " + toHex(addrZeroBlk) + '\n');

	ADDRINT current_addr = imp_start_addr;
	ADDRINT rel_addr = 0;
	vector<pair<ADDRINT, fn_info_t*>> result_vec;
	
	auto it1 = function_slots_in_rdata.begin();
	for (auto it2 : sorted_api_map) {
		fn_info_t *fninfo = it2.second;
		ADDRINT addr = *it1;
		result_vec.push_back(make_pair(addr, fninfo));
		it1++;
	}
	
	//for (auto it = sorted_api_map.begin(); it != sorted_api_map.end(); it++) {
	//	// assign resolved function address to candidate IAT area
	//	fn_info_t *fninfo = it->second;		
	//	result_vec.push_back(make_pair(current_addr - obf_img_saddr, it->second));
	//	current_addr += ADDRSIZE;
	//	idx++;
	//}

	// print IAT info
	*fout << "IAT START: " << toHex(imp_start_addr - main_img_saddr) << endl;
	*fout << "IAT SIZE: " << toHex(function_slots_in_rdata.size() * ADDRSIZE) << endl;
	/*for (auto it = result_vec.begin(); it != result_vec.end(); it++) {
		*fout << toHex(it->first) << "\taddr\t" << it->second->module_name << '\t' << it->second->name << endl;
	}*/

	for (auto it : result_vec)
	{
		*fout << toHex(it.first) << "\taddr\t" << it.second->module_name << '\t' << it.second->name << endl;
	}

}


// Find External Reference without a gap area
void FindExistingIAT()
{
	EXCEPTION_INFO *pExinfo = NULL;
	size_t img_size = main_img_eaddr - main_img_saddr;
	if (img_size > sizeof(memory_buffer)) {	
		*fout << "Image size too big. Please resize the buffer." << endl;
		((ofstream*)fout)->close();
		exit(0);
	}

	size_t numcopied = PIN_SafeCopyEx(memory_buffer, (VOID*)main_img_saddr, img_size, pExinfo);

	vector<pair<size_t, ADDRINT>> IATCandidates;
	
	for (size_t i = 0; i < numcopied; i += ADDRSIZE) {		
		// check whether the value of the current address points to a API function		
		ADDRINT target = TO_ADDRINT(memory_buffer + i);
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
		if (i1 - i0 > ADDRSIZE * 2) {
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
	//*fout << "IAT SIZE: " << toHex(idx * ADDRSIZE) << endl;
	//for (auto it = result_vec.begin(); it != result_vec.end(); it++) {
	//	*fout << toHex(it->first) << "\taddr\t" << it->second->module_name << '\t' << it->second->name << endl;
	//}
}


// API detect analysis function
void TRC_analysis(CONTEXT *ctxt, ADDRINT addr, UINT32 size, THREADID threadid)
{
	if (threadid != 0) return;
	// if (oep) *fout << toHex(addr) << endl;

#if DEBUG == 1

	* fout << toHex(addr) << ' '<< GetAddrInfo(addr) << endl;
#endif

	if (isCheckAPIRunning) {
#if LOG_CALL_CHECK == 1
		*fout << "# CheckAPI running " << toHex(addr) << ' ' << GetAddrInfo(addr) << endl;	
#endif

		ADDRINT caller_addr = current_obfuscated_call->caller_addr;
		ADDRINT prev_addr = 0;
		
		// start of the trace
		if (!traceAddrSeq.empty())
		{
			prev_addr = *traceAddrSeq.rbegin();
		}

		// limit trace length to prevent infinite loop
		if (traceAddrSeq.size() > 20)
		{
			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			goto check_api_start;
		}

		fn_info_t *fninfo = GetFunctionInfo(addr);
		ADDRINT stkptr = PIN_GetContextReg(ctxt, REG_STACK_PTR);
		
		traceAddrSeq.push_back(addr);
		traceSPSeq.push_back(stkptr);

		// check abnormal instruction
		size_t cnt = 0;
		for (auto ins_addr : *trace_cache_m[addr])
		{			
			string asmcode = asmcode_m[ins_addr];
			
			if (check_abnormal_ins(asmcode))
			{
				isCheckAPIStart = true;
				isCheckAPIRunning = false;
				goto check_api_start;
			}			
			// only check 10 instruction
			if (cnt++ > 10) break;			
		} 
		
#if LOG_CALL_CHECK == 1
		*fout << "# Checking : " << GetAddrInfo(addr) << " ESP:" << toHex(stkptr) << " T:" << toHex(addr) << endl;
		for (auto ins_addr : *trace_cache_m[addr])
		{
			*fout << "# " << toHex(ins_addr) << ' ' << asmcode_m[ins_addr] << endl;
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
				*fout << "# MOV Caller address: " << toHex(caller_addr) << endl;
				*fout << "# MOV return address: " << toHex(addr) << endl;
				*fout << "# MOV next to Caller address: " << toHex(trace_next_addr_m[caller_addr]) << endl;
				*fout << "# SP before mov call: " << toHex(traceSPSeq[0]) << endl;
				*fout << "# SP after mov call : " << toHex(stkptr) << endl;
#endif
				ADDRINT adjusted_caller_addr = addr - 6;
				ADDRINT api_fn_addr = movRegApiFnAddrs[set_api_reg].first;
				fninfo = GetFunctionInfo(api_fn_addr);

				*fout << toHex(adjusted_caller_addr - main_img_saddr) << "\tmov-" << REG_StringShort(set_api_reg) << '\t' << fninfo->module_name << '\t' << fninfo->name << endl;
				obfaddr2fn[current_obf_fn_addr] = fninfo;
				mov_obfaddr2fn[current_obf_fn_addr] = fninfo;				
			}
			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			goto check_api_start;						
		}

		// skip obfuscated code
		if (addr >= main_txt_eaddr && addr < main_img_eaddr)
		{
			return;
		}

		// if the trace not in in API function, skip
		if (fninfo == NULL || fninfo->name == ".text") return;

		// skip user exception by false positive find api calls
		if (fninfo->name.find("KiUserExceptionDispatcher") != string::npos)
		{			
			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			goto check_api_start;
		}

		// Check call/jmp
		// Compare stack top to check the return address which points to the next to the caller instruction. 		
		PIN_SafeCopy((VOID*)memory_buffer, (VOID*)stkptr, ADDRSIZE);
		ADDRINT stk_top_value = TO_ADDRINT(memory_buffer);
		ADDRINT original_addr;		
		ADDRINT adjusted_caller_addr;		
		string call_type;

		INT32 stk_diff = traceSPSeq[0] - stkptr;
		if (stk_diff != 0 && stk_diff != ADDRSIZE && stk_diff != -ADDRSIZE)
		{
			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			goto check_api_start;
		}
		
		original_addr = caller_addr;

		if (stk_top_value == caller_addr + 5 || stk_top_value == caller_addr + 6) {				
			call_type = "call";
			if (stk_diff == ADDRSIZE)
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
			else if (stk_diff == -ADDRSIZE)
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
		*fout << "# Caller address: " << toHex(caller_addr) << endl;
		*fout << "# return address: " << toHex(stk_top_value) << endl;
		*fout << "# next to Caller address: " << toHex(trace_next_addr_m[caller_addr]) << endl;
		*fout << "# SP before call: " << toHex(traceSPSeq[0]) << endl;
		*fout << "# SP at API function: " << toHex(stkptr) << endl;
		*fout << "# call type: " << call_type << endl;
#endif

		*fout << toHex(adjusted_caller_addr - main_img_saddr) << '\t' << call_type << '\t' << fninfo->module_name << '\t' << fninfo->name << endl;
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
		if (isRegSaved) {
			restore_regs(ctxt);
		}
		else {
			save_regs(ctxt);
			isRegSaved = true;
		}

		if (current_obf_fn_pos == obfuscated_call_candidate_addrs.size()) {
			// when checking obfuscated call finished, prepare the end 
			isCheckAPIStart = false;
			isCheckAPIEnd = true;

#if LOG_CALL_CHECK == 1
			*fout << "# Checking End " << current_obf_fn_pos << endl;
#endif

			goto check_api_end;
		}
		call_info_t *callinfo = obfuscated_call_candidate_addrs.at(current_obf_fn_pos++);
#if LOG_CALL_CHECK == 1
		*fout << "# Checking : " << toHex(callinfo->caller_addr) << ' ' << current_obf_fn_pos << '/' << obfuscated_call_candidate_addrs.size() << endl;				
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
		if (FindGap()) {
#if LOG_CALL_CHECK == 1
			*fout << "# Searching for IAT - Gap" << endl;
#endif
			CheckExportFunctions();
		}
		else {
#if LOG_CALL_CHECK == 1
			*fout << "# Searching for IAT - No Gap" << endl;
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
	for (REG reg : regs_ctx) {
		PIN_SetContextReg(ctxt, reg, regs_saved[reg]);
	}
}

void save_regs(LEVEL_VM::CONTEXT * ctxt)
{
	for (REG reg : regs_ctx) {
		regs_saved[reg] = PIN_GetContextReg(ctxt, reg);
	}
}

REG check_api_fn_assignment_to_register(LEVEL_VM::CONTEXT * ctxt)
{
	REG set_api_reg = REG_NONE;
	for (REG reg : regs_for_obfuscation) {
		ADDRINT reg_val = PIN_GetContextReg(ctxt, reg);
		fn_info_t *fn = GetFunctionInfo(reg_val);
#if LOG_CALL_CHECK == 1
		*fout << "# MOV " << REG_StringShort(reg) << ", " << toHex(reg_val) << ' ';
#endif
		if (fn)
		{			
			set_api_reg = reg;
			movRegApiFnAddrs[reg] = make_pair(reg_val, fn->detailed_name());
#if LOG_CALL_CHECK == 1
			*fout << fn->detailed_name();
#endif
		}
#if LOG_CALL_CHECK == 1
		*fout << endl;		
#endif
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
	string abnormal_ins_set[] = { "leave ", "in ", "out ", "far ", "hlt ", "mov esp"};
	for (auto ins : abnormal_ins_set)
	{
		if (disasm.find(ins) != string::npos) return true;
	}	
	return false;
}

// EXE trace instrumentation function
void TRC_inst(TRACE trace, void *v)
{
	ADDRINT addr = TRACE_Address(trace);
	
	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)TRC_analysis,
		IARG_CONTEXT,
		IARG_ADDRINT, addr,
		IARG_UINT32, TRACE_Size(trace), 
		IARG_THREAD_ID,
		IARG_END);

	trace_cache_m[addr] = new vector<ADDRINT>;
	trace_next_addr_m[addr] = addr + TRACE_Size(trace);

	// Instrument memory write to find OEP in executable
	// and set instruction cache	
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			ADDRINT insaddr = INS_Address(ins);
			asmcode_m[insaddr] = INS_Disassemble(ins);			
			trace_cache_m[addr]->push_back(insaddr);

			if (!isDLLAnalysis && INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins))
			{
				// *fout << "MWC:" << toHex(insaddr) << ' ' << asmcode_m[insaddr] << endl;
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)INS_MW_analysis,
					IARG_MEMORYWRITE_EA,
					IARG_ADDRINT, insaddr, 
					IARG_END);
			}
		}
	}

	// OEP detection for EXE and
	// DLL unpack finish detection for DLL	
	if (isDLLAnalysis)
	{
		// DLL unpack detection
		if (addr == obf_dll_entry_addr) {
			is_unpack_started = true;
		}

		// Unpacking DLL is done after executing DLLEntry. 
		// After DLLEntry function is executed, return to DLL Loader or the DllMain in the text section is executed. 
		if (is_unpack_started && ((addr >= loader_saddr && addr < loader_eaddr) || (addr >= main_txt_saddr && addr < main_txt_eaddr)))
		{
			if (!isFoundAPICalls) {
				FindObfuscatedAPICalls();
				isCheckAPIStart = true;
			}
		}
	}
	else
	{
		if (addr >= main_txt_saddr && addr < main_txt_eaddr)
		{
			// find OEP 
			if (oep == 0) {
				set_meblock(addr);
				// vmprotect without packing option
				if (1) // get_mwblock(addr) && get_meblock(addr) == 1)
				{
					BBL bbl = TRACE_BblHead(trace);
					INS ins = BBL_InsHead(bbl);

					if (!INS_IsRet(ins) /* && !INS_IsCall(ins)*/) {
						oep = addr;
						*fout << "OEP:" << toHex(oep - main_img_saddr) << endl;
						FindObfuscatedAPICalls();
						isCheckAPIStart = true;
					}
				}
			}
		}
	}
}

// EXE INS memory write analysis function 
void INS_MW_analysis(ADDRINT targetAddr, ADDRINT insaddr)
{	
#if LOG_MEMORY_WRITE == 1
	*fout << "# MW:" << toHex(insaddr) << "->" << toHex(targetAddr) << endl;
#endif
	set_mwblock(targetAddr);	
}


// ========================================================================================================================
// Thread Instrumentation
// ========================================================================================================================

// This routine is executed every time a thread is created.
VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	thr_cnt++;
#if LOG_THREAD == 1
	*fout << "# Starting Thread " << threadid << endl;
#endif
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
#if LOG_THREAD == 1
	*fout << "# Ending Thread " << threadid << endl;
#endif
	thread_ids.erase(threadid);
}



// ===============
// 
// ===============

bool CheckExportArea_x64(int step)
{
	bool retVal = false;
	size_t txtsize = main_txt_eaddr - main_txt_saddr;;
	UINT8 *buf = (UINT8*)malloc(txtsize);
	// buf has executable memory image
	PIN_SafeCopy(buf, (VOID*)main_txt_saddr, txtsize);

	// step 1: find zero block
	if (step == 1) {
		bool isZeroBlk = true;
		if (imp_start_addr != 0) goto free_buf;
		imp_start_addr = 0;

		for (size_t blk = 0; blk < txtsize; blk += 0x1000) {
			isZeroBlk = true;
			for (size_t i = 0; i < 0x1000; i++) {
				if (buf[blk + i] != 0) {
					isZeroBlk = false;
					break;
				}
			}
			if (isZeroBlk) {
				imp_start_addr = main_txt_saddr + blk;
				retVal = true;
				goto free_buf;
			}
		}
	}
	// step 2: check whether the zero block is filled
	else if (step == 2) {
		bool isZeroBlk = true;
		if (imp_start_addr == 0) {
			retVal = false;
			goto free_buf;
		}
		for (size_t i = 0; i < 0x1000; i++) {
			if (buf[imp_start_addr - main_txt_saddr + i] != 0) {
				retVal = true;
				goto free_buf;
			}
		}
	}

free_buf:
	free(buf);
	// *fout << toHex(addrZeroBlk) << endl;
	return retVal;
}


// ========================================================================================================================
// Executable Image Instrumentation
// ========================================================================================================================

// IMG instrumentation function for EXE files
void IMG_inst(IMG img, void *v)
{
	// Trim image name
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

	*fout << "IMG:" << *modinfo << endl;

	if (isDLLAnalysis)
	{
		// obfuscated dll module is loaded
		if (imgname == obf_dll_name)
		{
			obf_dll_entry_addr = IMG_Entry(img);
			main_img_saddr = saddr;
			main_img_eaddr = eaddr;

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
#ifdef TARGET_IA32E
		// for 64 bit application check IAT candidate first
		if (IMG_IsMainExecutable(img) || imgname == obf_dll_name)
		{
			CheckExportArea_x64(1);
		}
#endif
	}
	else
	{
		// EXE analysis
		if (IMG_IsMainExecutable(img))
		{
			main_img_saddr = saddr;
			main_img_eaddr = eaddr;

			// *fout << toHex(instrc_saddr) << ' ' << toHex(instrc_eaddr) << endl;
			SEC sec = IMG_SecHead(img);
			main_txt_saddr = SEC_Address(sec);
			main_txt_eaddr = main_txt_saddr + SEC_Size(sec);

#ifdef TARGET_IA32E
			// for 64 bit application check IAT candidate first
			CheckExportArea_x64(1);
#endif
		}
	}

	// Record each section and function data
	size_t cnt = 0;
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec), cnt++)
	{
		string secname = SEC_Name(sec);
		ADDRINT saddr = SEC_Address(sec);
		ADDRINT eaddr = saddr + SEC_Size(sec);
		sec_info_t *secinfo = new sec_info_t(imgname, secname, saddr, eaddr);
		modinfo->sec_infos.push_back(secinfo);
		
		*fout << "SECTION:" << *secinfo << endl;

		if (SEC_Name(sec) == ".text" || cnt == 0)
		{
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
		else if (SEC_Name(sec) == ".rdata" && (!isDLLAnalysis && IMG_IsMainExecutable(img) || isDLLAnalysis && imgname == obf_dll_name)) {
			obf_rdata_saddr = SEC_Address(sec);
			obf_rdata_eaddr = obf_rdata_saddr + SEC_Size(sec);
		}
	}
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
	if (outputFileName == "result.txt")
	{		
		outputFileName = string(argv[argc - 1]) + ".txt";	
	}		
	fout = new ofstream(outputFileName.c_str());	

	obf_dll_name = KnobDLLFile.Value();
	if (obf_dll_name != "") {
		isDLLAnalysis = true;

		*fout << "TYPE:DLL" << endl;
		*fout << "NAME:" << obf_dll_name << endl;

		TO_LOWER(obf_dll_name);
		size_t pos = obf_dll_name.rfind("\\");	
		if (pos != string::npos) obf_dll_name = obf_dll_name.substr(pos + 1);		
	}
	else {		
		*fout << "TYPE:EXE" << endl;
		*fout << "NAME:" << string(argv[argc - 1]) << endl;
	}

	isDirectCall = KnobDirectCall.Value();
	
	PIN_InitSymbols();

	// Register Analysis routines to be called when a thread begins/ends
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	// Image Instrumentation
	IMG_AddInstrumentFunction(IMG_inst, 0);

	// Register function to be called to instrument traces
	TRACE_AddInstrumentFunction(TRC_inst, 0);

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
