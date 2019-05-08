#include "ThemidaPinAnalyzer.h"
#include "Config.h"
namespace WINDOWS {
#include <Windows.h>
}
using namespace std;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool", "o", "result.txt", "specify file name for the result");
KNOB<BOOL> KnobDump(KNOB_MODE_WRITEONCE, "pintool", "dump", "", "save memory dump");
KNOB<string> KnobDLLFile(KNOB_MODE_WRITEONCE, "pintool", "dll", "", "specify packed dll file");
KNOB<string> KnobPackerType(KNOB_MODE_WRITEONCE, "pintool", "packer", "themida", "packer type: themida2, themida3, vmp or enigma");
KNOB<BOOL> KnobDirectCall(KNOB_MODE_WRITEONCE, "pintool", "direct", "", "direct call");

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


// register save & restore
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


///////////////////////
static PIN_THREAD_UID unpack_thread_uid;
static PIN_THREAD_UID resolve_api_thread_uid;
PIN_SEMAPHORE sem_oep_found;
PIN_SEMAPHORE sem_resolve_api_end;
PIN_SEMAPHORE sem_unpack_finished;
PIN_SEMAPHORE sem_dump_finished;

///////////////////////


// dump memory of each section
void dump_memory()
{	
	mod_info_t *modinfo = GetModuleInfo(main_img_saddr);
	if (modinfo == NULL) return;
	
	size_t max_blk_size = 0;
	for (auto it = modinfo->sec_infos.begin(); it != modinfo->sec_infos.end(); it++)
	{
		sec_info_t *secinfo = *it;		
		max_blk_size = max(max_blk_size, secinfo->eaddr - secinfo->saddr);		
	}

	UINT8 *mem_buf = (UINT8*)malloc(max_blk_size);
	
	for (auto it = modinfo->sec_infos.begin(); it != modinfo->sec_infos.end(); it++)
	{
		sec_info_t *secinfo = *it;
		size_t size = secinfo->eaddr - secinfo->saddr;
		*fout << "DUMP_START" << *secinfo << endl;
		PIN_SafeCopy(mem_buf, (VOID*)secinfo->saddr, size);

		for (size_t idx = 0; idx < size; idx++) {
			*fout << toHex1(mem_buf[idx]);
			if (idx % 64 == 63) *fout << endl;
		}
		if (size % 64 != 0) *fout << endl;
		*fout << "DUMP_END" << endl;
	}

}



// ========================================================================================================================
// API Detection Functions 
// ========================================================================================================================

/// Find obfuscated API Calls
void FindObfuscatedAPICalls()
{	
	size_t scan_area_size = main_txt_eaddr - main_txt_saddr;
	//if (packer_type == "themida") {
	//	scan_area_size = main_img_eaddr - main_img_saddr;
	//}
	//else if (packer_type == "enigma") {
	//	scan_area_size = main_txt_eaddr - main_txt_saddr;
	//}

	UINT8 *buf = (UINT8*)malloc(scan_area_size);
	UINT8 *bufp, *bufp2;
	size_t idx, idx2;
	ADDRINT addr, addr2, target_addr;
	ADDRINT iat_start_addr = 0, iat_size = 0;
	
	sec_info_t *current_section = NULL, *target_section = NULL;	

	unsigned char* pc = reinterpret_cast<unsigned char*>(main_txt_saddr);

	// buf has executable memory image
	EXCEPTION_INFO *pExinfo = NULL;

	size_t numcopied = PIN_SafeCopyEx(buf, pc, scan_area_size, pExinfo);

	// search for address modification in program

	if (packer_type == "themida" || packer_type == "enigma") 
	{
		for (bufp = buf, idx = 0; idx < numcopied - 6; idx++, bufp++)
		{
			if (ADDRSIZE == 4)
			{
				// Themida x86
				// --------------
				// CALL r/m32 (FF 1F __ __ __ __)
				// is patched by Themida into
				// CALL rel32; NOP (E8 __ __ __ __ 90)
				// CALL rel32; NOP (90 E8 __ __ __ __)
				if (*bufp == 0xE8 && bufp[5] == 0x90)
				{

					addr = main_txt_saddr + idx;
					target_addr = addr + 5 + TO_UINT32(bufp + 1);

					if (obfaddr2fn.find(target_addr) != obfaddr2fn.end())
					{
						fn_info_t *fn = obfaddr2fn[target_addr];
						string modstr = fn->module_name;
						string fnstr = fn->name;
						string reladdr = toHex(addr - main_img_saddr);
						*fout << reladdr << "\tcall " << modstr << '\t' << fnstr << endl;
					}
				}
				
				else if (*bufp == 0x90 && bufp[1] == 0xE8)
				{

					addr = main_txt_saddr + idx;
					target_addr = addr + 6 + TO_UINT32(bufp + 2);

					if (obfaddr2fn.find(target_addr) != obfaddr2fn.end())
					{
						fn_info_t *fn = obfaddr2fn[target_addr];
						string modstr = fn->module_name;
						string fnstr = fn->name;
						string reladdr = toHex(addr - main_img_saddr);
						*fout << reladdr << "\tcall " << modstr << '\t' << fnstr << endl;
					}
				}

				// Enigma Protector x86
				// ---------------------
				// Enigma Protector preserve CALL r/m32
				// CALL [addr] (FF 15 __ __ __ __)
				// But the address points to allocated memory area
				// where the API function is copied into. 
				else if (*bufp == 0xFF && bufp[1] == 0x15)
				{
					// addr: current address
					// addr2: redirection address in bracket
					// target_addr: real API address
					addr = main_txt_saddr + idx;
					sec_info_t *tmp_sec = GetSectionInfo(addr);

					if (current_section == NULL) {
						current_section = tmp_sec;
					}
					else if (current_section != tmp_sec) {
						break;
					}

					bufp2 = bufp + 2;
					addr2 = TO_ADDRINT(bufp2);
					// *fout << toHex(addr) << " call [" << toHex(addr2) << ']' << endl;
					idx2 = addr2 - main_txt_saddr;

					// skip malformed address
					// address should be inside the image
					if (idx2 > scan_area_size) continue;

					bufp2 = buf + idx2;
					target_addr = TO_ADDRINT(bufp2);

					// *fout << '[' << toHex(addr2) << "]=" << toHex(target_addr);

					if (obfaddr2fn.find(target_addr) != obfaddr2fn.end())
					{
						fn_info_t *fn = obfaddr2fn[target_addr];

						string modstr = fn->module_name;
						string fnstr = fn->name;
						string reladdr = toHex(addr - main_img_saddr);
						*fout << reladdr << "\tcall " << modstr << '\t' << fnstr << endl;
					}
				}
			}
			else if (ADDRSIZE == 8)
			{
				// CALL r/m32 (FF 1F __ __ __ __)
				// is patched by Themida64 into
				// CALL rel32; db 00 (E8 __ __ __ __ ; 00)
				if (*bufp == 0xE8 && (bufp[5] == 0x00 || bufp[5] == 0x90))
				{
					addr = main_txt_saddr + idx;
					target_addr = addr + 5 + TO_UINT32(bufp + 1);
					current_section = GetSectionInfo(addr);
					target_section = GetSectionInfo(target_addr);
					if (current_section == NULL || target_section == NULL) continue;
					// obfuscated call target is selected by 
					// - call targets into other section of the main executables				

					if (current_section->module_name == target_section->module_name &&
						current_section->saddr != target_section->saddr) {
						if (check_ins_valid(addr)) {
							obf_call_candidate_addrs.push_back(obf_call_t(addr, target_addr, INDIRECT_CALL, "", false));
						}
					}
				}
			}
		}
	}
	else if (packer_type == "vmp")
	{
		for (idx = 0; idx < numcopied - 6; idx++)
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
				// caller_addr-1: CALL imm32 # (48) FF 15 __ __ __ __	: 6 bytes or 7 bytes (with REX.W prefix)
				// ->
				// caller_addr-1: PUSH r32		# 50~57 1 bytes
				// caller_addr  : CALL ___ # (48) E8 __ __ __ __ : 5 bytes or 6 bytes (with REX.W prefix)		

				// PATTERN 2-2: CALL indirect -> CALL imm32; RET or NOP or INT3
				// caller_addr  : CALL ___ # (48) FF 15 __ __ __ __	: 6~7 bytes
				// ->
				// caller_addr  : CALL ___ # (48) E8 __ __ __ __ : 5~6 bytes
				// caller_addr+5: NOP or RET or INT3 # 90 or C3 or CC : 1 byte


				// PATTERN 3-1: JMP indirect -> PUSH r32; CALL imm32
				// -----------------------------------------------------------------
				// caller_addr-1: JMP ___ # (48) FF 25 __ __ __ __	: 6 bytes or 7 bytes (with REX.W prefix)
				// ->
				// caller_addr-1: PUSH r32		# 50~57 1 bytes
				// caller_addr  : CALL ___ # (48) E8 __ __ __ __ : 5 bytes or 6 bytes (with REX.W prefix)			


				// PATTERN 3-2: JMP indirect -> CALL imm32; RET or NOP
				// -----------------------------------------------------------------
				// caller_addr  : JMP ___ # (48) FF 25 __ __ __ __	: 6 bytes or 7 bytes (with REX.W prefix)
				// ->
				// caller_addr  : CALL ___ # (48) E8 __ __ __ __ : 5 bytes or 6 bytes (with REX.W prefix)
				// caller_addr+5: NOP or RET # 90 or C3 : 1 byte


				size_t pattern_before_push_reg = 0;				
				bool has_rexw = false;

				// check rex.w
				if (ADDRSIZE == 8 && buf[idx - 1] == 0x48) {
					has_rexw = true;
				}


				// push reg at caller_addr : PATTERN 1-1, 2-1, 3-1
				if (buf[idx - 1] >= 0x50 && buf[idx - 1] <= 0x57) {
					pattern_before_push_reg = 1;
					// sometimes vmprotect add rex.w prefix
					if (ADDRSIZE == 8 && buf[idx - 2] == 0x48) {						
						pattern_before_push_reg++;
					}						
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
					if (has_rexw) addr--;
					obf_call_candidate_addrs.push_back(obf_call_t(addr, target_addr, INDIRECT_CALL, "", pattern_before_push_reg));
				}
			}
		}
	}

	free(buf);
}


bool FindIATArea()
{
	bool retVal = false;

	if (packer_type == "vmp")
	{
		imp_start_addr = obf_rdata_saddr;
		imp_end_addr = obf_rdata_eaddr;
		found_IAT = false;
		return true;
	}

	size_t txtsize = main_txt_eaddr - main_txt_saddr;
	if (packer_type == "enigma")
	{
		txtsize += 0x1000;
	}
		
	UINT8 *buf = (UINT8*)malloc(txtsize);
	// buf has executable memory image
	PIN_SafeCopy(buf, (VOID*)main_txt_saddr, txtsize);

	// Search for Imports
	size_t num_imp_fn = 0;
	size_t num_consecutive_not_imp_fn = 0;
	UINT8 *bufp;
	ADDRINT addr, i;
	mod_info_t *mod;
	for (size_t blk = 0; blk < txtsize; blk += 0x1000) {		
		imp_list.clear();		
		for (i = 0; i < 0x1000; i += ADDRSIZE) {
			bufp = buf + blk + i;
			addr = TO_ADDRINT(bufp);			

#if TARGET_IA32
			auto it = obfaddr2fn.find(addr);
			// if target_addr is obfuscated function address
			if (it != obfaddr2fn.end())
			{
				addr2fnaddr[addr] = it->second->saddr;
				imp_list.push_back(it->second);
				num_consecutive_not_imp_fn = 0;
				num_imp_fn++;
				continue;
			}
#endif
			mod = GetModuleInfo(addr);			
			if (addr == 0 || mod == NULL) {
				if (++num_consecutive_not_imp_fn > 1) {
					break;
				}
				imp_list.push_back(NULL);
				continue;
			}

			num_consecutive_not_imp_fn = 0;
			num_imp_fn++;
			imp_list.push_back(GetFunctionInfo(addr));			
		}

		if (num_imp_fn > 3) {	// assumption: at least 3 import function
			imp_start_addr = main_txt_saddr + blk;
			imp_end_addr = main_txt_saddr + blk + i;
			found_IAT = true;
			retVal = true;
			goto free_buf;
		}
	}

	// find zero block with interval 0x1000
	if (imp_start_addr != 0) goto free_buf;
	imp_start_addr = 0;
		
	for (size_t blk = 0; blk + obf_call_candidate_addrs.size() * ADDRSIZE < txtsize; blk += 0x1000) {
		found_zero_blk = true;
		for (size_t i = 0; i < obf_call_candidate_addrs.size() * ADDRSIZE; i++) {
			if (buf[blk + i] != 0) {
				found_zero_blk = false;
				break;
			}
		}
		if (found_zero_blk) {
			imp_start_addr = main_txt_saddr + blk;
			*fout << "# iat candidate:" << toHex(imp_start_addr) << endl;
			retVal = true;
			goto free_buf;
		}
	}
	
	// find zero block with interval 0x100
	*fout << "# 2" << endl;
	for (size_t blk = 0; blk + obf_call_candidate_addrs.size() * ADDRSIZE < txtsize; blk += 0x100) {
		found_zero_blk = true;
		for (size_t i = 0; i < obf_call_candidate_addrs.size() * ADDRSIZE; i++) {
			if (buf[blk + i] != 0) {
				found_zero_blk = false;
				break;
			}
		}
		if (found_zero_blk) {
			imp_start_addr = main_txt_saddr + blk;
			*fout << "# iat candidate:" << toHex(imp_start_addr) << endl;

			retVal = true;
			goto free_buf;
		}
	}
	
	// If there is no concave, select idata 
	*fout << "# 3" << endl;	
	imp_start_addr = obf_idata_saddr;
	*fout << "# iat candidate:" << toHex(imp_start_addr) << endl;

	retVal = true;	

free_buf:
	free(buf);
	// *fout << toHex(addrZeroBlk) << endl;
	return retVal;
}

// Check External Reference from main image address
void PrintIATArea()
{

	// print IAT information if IAT is found (themida x64)
	if (found_IAT) {
		ADDRINT addr;
		*fout << "IAT START: " << toHex(imp_start_addr - main_img_saddr) << endl;
		addr = imp_start_addr;
		for (fn_info_t *fn : imp_list) {
			if (fn != NULL) {
				*fout << toHex(addr - main_img_saddr) << "\taddr\t" << fn->module_name << '\t' << fn->name << endl;
			}			
			addr += ADDRSIZE;
		}
		*fout << "IAT SIZE: " << toHex((addr - imp_start_addr) / ADDRSIZE) << endl;
		return;
	}

	size_t blksize = GetSectionInfo(imp_start_addr)->eaddr - imp_start_addr;
	UINT8 *buf = (UINT8*)malloc(blksize);
	PIN_SafeCopy(buf, (VOID*)imp_start_addr, blksize);

	// Build sorted_api_map to gather functions per dll: function name -> fninfo. 
	map<string, fn_info_t*> sorted_api_map;
	for (auto it = obfaddr2fn.begin(); it != obfaddr2fn.end(); it++) {
		fn_info_t *fninfo = it->second;
		string key = fninfo->module_name + '.' + fninfo->name;
		sorted_api_map[key] = fninfo;		
	}

	// Resolve obfuscated API call
	ADDRINT current_addr = imp_start_addr;
	ADDRINT rel_addr = 0;
	size_t idx = 0;
	vector<pair<ADDRINT, fn_info_t*>> result_vec;
	string prev_mod_name = "";
	for (auto it = sorted_api_map.begin(); it != sorted_api_map.end(); it++, idx++) {	
		// assign resolved function address to candidate IAT area
		fn_info_t *fninfo = it->second;		
		result_vec.push_back(make_pair(current_addr - main_img_saddr, it->second));
		current_addr += ADDRSIZE;
		if (fninfo && prev_mod_name != fninfo->module_name) current_addr += ADDRSIZE;
		prev_mod_name = fninfo->module_name;
	}

	// print IAT info
	*fout << "IAT START: " << toHex(imp_start_addr - main_img_saddr) << endl;
	*fout << "IAT SIZE: " << toHex(idx * ADDRSIZE) << endl;
	for (auto it = result_vec.begin(); it != result_vec.end(); it++) {
		*fout << toHex(it->first) << "\taddr\t" << it->second->module_name << '\t' << it->second->name << endl;
	}
	free(buf);

}


// API Detect executable trace analysis function
void TRC_analysis(CONTEXT *ctxt, ADDRINT addr, THREADID threadid)
{	
	if (threadid != 0) return;
	
	// Check OEP
	if (oep == 0)
	{
		set_meblock(addr);
		if (addr >= main_txt_saddr && addr < main_txt_eaddr)
		{
			if (get_mwblock(addr) && get_meblock(addr) == 1)
			{
				oep = addr;
				*fout << "OEP:" << toHex(oep - main_img_saddr) << endl;
				PIN_SaveContext(ctxt, &ctx0);
				PIN_SemaphoreSet(&sem_oep_found);				
			}
			return;
		}
	}

	if (isCheckAPIRunning) {
		// if obfuscated API checking is started and 
		// if the trace is in another section
		// then here is the obfuscated instructions that resolve 'call API_function'
		// These obfuscated instructions end by 'RET' instruction 
		// that jumps into API function code

		ADDRINT caller_addr = current_obfuscated_call->srcaddr;
		ADDRINT prev_addr = 0;

		UINT8 buf[8];		
		ADDRINT stkptr = PIN_GetContextReg(ctxt, REG_STACK_PTR);		
		PIN_SafeCopy(buf, (VOID*)stkptr, 8);

		traceAddrSeq.push_back(addr);
		traceSPSeq.push_back(stkptr);

#if LOG_CALL_CHECK == 1
		* fout << "# CheckAPI running " << toHex(addr) << ' ' << GetAddrInfo(addr) << " # " << traceAddrSeq.size() << endl;
#endif

		if (traceAddrSeq.size() > 100)
		{
			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			goto check_api_start;
		}

		if (addr > main_txt_eaddr && addr < main_img_eaddr) {
			// DO NOTHING
			return;
		}

		// if the trace in in API function
		// then here is the API function. 
		// Check the stack top value whether the value is next address of the call instruction. 
				
		fn_info_t *fninfo = GetFunctionInfo(addr);

		if (fninfo == NULL) return;

		// skip user exception by false positive find api calls
		if (fninfo->name.find("KiUserExceptionDispatcher") != string::npos)
		{
			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			goto check_api_start;
		}

		if (packer_type == "themida" || packer_type == "enigma")
		{
			if (TO_ADDRINT(buf) == current_callnextaddr) {

				*fout << toHex(current_calladdr - main_img_saddr) << "\tcall\t";
			}
			else {
				*fout << toHex(current_calladdr - main_img_saddr) << "\tgoto\t";
			}

			*fout << fninfo->module_name << '\t' << fninfo->name << endl;

			obfaddr2fn[current_obf_fn_addr] = fninfo;

			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			goto check_api_start;
		}
		else if (packer_type == "vmp")
		{
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
					adjusted_caller_addr = caller_addr - current_obfuscated_call->prev_push_inst_size;
				}
				else
				{
					isCheckAPIStart = true;
					isCheckAPIRunning = false;
					goto check_api_start;
				}
			}

#if LOG_CALL_CHECK == 1
			* fout << "# Caller address: " << toHex(caller_addr) << endl;
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
		
	}

check_api_start:
	// For each obfuscated call instruction,
	// check whether the execution trace go into API function.
	// Therefore IP is changed into obfuscated function call one by one
	if (isCheckAPIStart) {


		// register context save & restore
		if (isRegSaved) {
			restore_regs(ctxt);
		}
		else {
			save_regs(ctxt);
			isRegSaved = true;
		}

		// *fout << "# current function: " << current_obf_fn_pos << '/' << obf_call_candidate_addrs.size() << endl;
		if (current_obf_fn_pos == obf_call_candidate_addrs.size()) {
			// when checking obfuscated call finished, prepare the end 
			isCheckAPIStart = false;
			isCheckAPIEnd = true;
#if LOG_CALL_CHECK == 1
			* fout << "# Checking End " << current_obf_fn_pos << endl;
#endif
			goto check_api_end;
		}
		obf_call_t *addrp = &obf_call_candidate_addrs.at(current_obf_fn_pos++);
		ADDRINT calladdr = addrp->srcaddr;
		ADDRINT tgtaddr = addrp->dstaddr;
		
#if LOG_CALL_CHECK == 1
		* fout << "# Checking : " << toHex(addrp->srcaddr) << ' ' << current_obf_fn_pos << '/' << obf_call_candidate_addrs.size() << endl;
#endif
		traceAddrSeq.clear();
		traceSPSeq.clear();
		movRegApiFnAddrs.clear();

		// currently call instruction is of the form 'E8 __ __ __ __' which is 5 bytes
		// but originally it is 'FF 15 __ __ __ __' or 'FF 25 __ __ __ __' which is 6 bytes
		// so next instruction address is addr + 6
		current_calladdr = calladdr;
		current_callnextaddr = calladdr + 6;
		current_obfuscated_call = addrp;

		isCheckAPIStart = false;
		isCheckAPIRunning = true;
		traceAddrSeq.clear();

		current_obf_fn_addr = tgtaddr;
		
		// change IP to obfuscated function call target

		// fill the stack top with the stack top address to avoid access violation
		// 128 bytes (= 16 QWORD addresses) are filled. 
		/*ADDRINT stkptr = PIN_GetContextReg(ctxt, REG_STACK_PTR);
		*fout << "RSP = " << toHex(stkptr) << endl;
		UINT8 buf[8];
		ADDRINT tmp = stkptr;
		for (size_t i = 0; i < 8; i++) {
			buf[i] = (UINT8)tmp;
			tmp >>= 8;
		}
		PIN_SetContextReg(ctxt, REG_STACK_PTR, stkptr - 128);
		for (ADDRINT tmpaddr = stkptr - 8; tmpaddr >= stkptr - 128; tmpaddr -= 8) {
			PIN_SafeCopy((VOID*)tmpaddr, buf, 8);
		}
		*/
		PIN_SetContextReg(ctxt, REG_INST_PTR, calladdr);
		PIN_ExecuteAt(ctxt);
	}

check_api_end:
	if (isCheckAPIEnd) {
		// after checking obfuscated calls, terminate.
		LOG("Calling CheckExportFunctions_x64 in TRC_analysis_x64\n");
		PIN_SemaphoreSet(&sem_resolve_api_end);
		PIN_SemaphoreWait(&sem_dump_finished);
		// CheckExportFunctions_x64();
		((ofstream*)fout)->close();
		PIN_ExitProcess(-1);
		return;
	}
}

// API Detect executable trace instrumentation function
void TRC_inst(TRACE trace, void *v)
{
	ADDRINT addr = TRACE_Address(trace);
	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)TRC_analysis,
		IARG_CONTEXT,
		IARG_ADDRINT, addr,
		IARG_THREAD_ID,
		IARG_END);

	trace_cache_m[addr] = new vector<ADDRINT>;
	trace_next_addr_m[addr] = addr + TRACE_Size(trace);


#if DEBUG == 1
	if (addr >= main_img_saddr && addr < main_img_eaddr) {
		*fout << "Trace:" << toHex(addr) << endl;
	}
#endif
	
	// instrument each memory read/write instruction
	// and
	// check unsupported instructions
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			if (INS_IsFarRet(ins))
			{
				isCheckAPIStart = true;
				isCheckAPIRunning = false;
				*fout << "# Far Ret !!!" << endl;
			}
			if (INS_Mnemonic(ins) == "XRSTOR") continue;
			UINT32 memOperands = INS_MemoryOperandCount(ins);

			if (packer_type == "enigma")
			{
				// Iterate over each memory operand of the instruction.
				for (UINT32 memOp = 0; memOp < memOperands; memOp++)
				{
					if (INS_MemoryOperandIsRead(ins, memOp) && !INS_IsStackRead(ins))
					{
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)INS_MR_analysis,
							IARG_MEMORYREAD_EA,
							IARG_END);
					}				
				}
			}

			if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins))
			{							
				// record write addresses to detect OEP
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)INS_MW_analysis,
					IARG_MEMORYWRITE_SIZE,
					IARG_MEMORYWRITE_EA,
					IARG_END);
			}
		}
	}
}


// ========================================================================================================================
// API Detection Functions for x86
// ========================================================================================================================


// IAT fixing
void FixIAT()
{	
	for (auto it = addr2fnaddr.begin(); it != addr2fnaddr.end(); it++)
	{
		ADDRINT srcaddr = it->first;
		ADDRINT dstaddr = it->second;
		//fn_info_t *dstfn = GetFunctionInfo(dstaddr);
		//if (dstfn == NULL) *fout << toHex(srcaddr - main_img_saddr) << "\taddr " << toHex(dstaddr) << endl;
		//else *fout << toHex(srcaddr - main_img_saddr) << "\taddr " << dstfn->module_name << '\t' << dstfn->name << endl;

		unsigned char* pc = reinterpret_cast<unsigned char*>(srcaddr);
		PIN_SafeCopy(pc, &dstaddr, ADDRSIZE);
	}
}

// call/goto fixing
void FixCall()
{
	for (auto it = obf_call_candidate_addrs.begin(); it != obf_call_candidate_addrs.end(); it++)
	{
		obf_call_t obf_call = *it;
		unsigned char* pc = reinterpret_cast<unsigned char*>(obf_call.srcaddr);
		UINT8 byts[7];
		size_t sz = obf_call.to_bytes(byts);
		PIN_SafeCopy(pc, byts, sz);
	}
}


/// <summary> Instrument instructions. </summary>
void INS_inst(INS ins, void *v)
{
	ADDRINT addr = INS_Address(ins);
	if (isDLLAnalysis)
	{
		if (addr == obf_dll_entry_addr) {
			is_unpack_started = true;
			LOG("Unpack Started.\n");
		}
		if (!is_unpack_started) return;
	}

	INS_InsertCall(ins, IPOINT_BEFORE, 
		(AFUNPTR)INS_analysis,
		IARG_CONTEXT, 
		IARG_ADDRINT, addr,
		IARG_THREAD_ID,
		IARG_END);

	// Iterate over each memory operand of the instruction.
	size_t memOperands = INS_MemoryOperandCount(ins);
	for (size_t memOp = 0; memOp < memOperands; memOp++)
	{
		// Check each memory operand
		if (INS_Mnemonic(ins) == "XRSTOR") continue;
		if (INS_MemoryOperandIsRead(ins, memOp) && !INS_IsStackRead(ins))
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)INS_MR_analysis,
				IARG_MEMORYREAD_EA,
				IARG_END);
		}
		if (INS_MemoryOperandIsWritten(ins, memOp) && !INS_IsStackWrite(ins))
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)INS_MW_analysis,
				IARG_MEMORYWRITE_SIZE,
				IARG_MEMORYWRITE_EA,
				IARG_END);
		}
	}
}



// INS analysis function
// Just record previous address
void INS_analysis(CONTEXT *ctxt, ADDRINT addr, THREADID tid)
{
	if (tid != 0) return;
	// Check OEP
	if (oep == 0)
	{		
		// if (isDLLAnalysis)
		// {
		// 	// Unpacking DLL is done after executing DLLEntry. 
		// 	// After DLLEntry function is executed, return to DLL Loader or the DllMain in the text section is executed. 
		// 	if (is_unpack_started && ((addr >= loader_saddr && addr < loader_eaddr) || (addr >= main_txt_saddr && addr < main_txt_eaddr)))
		// 	{
		// 		PrintIATArea();
		// 		((ofstream*)fout)->close();
		// 		PIN_ExitProcess(-1);
		// 	}
		// }
		
		set_meblock(addr);
		if (addr >= main_txt_saddr && addr < main_txt_eaddr)
		{
			if (get_mwblock(addr) && get_meblock(addr) == 1)
			{
				oep = addr;
				*fout << "OEP:" << toHex(oep - main_img_saddr) << endl;
				PIN_SaveContext(ctxt, &ctx0);
				PIN_SemaphoreSet(&sem_oep_found);
			}
			return;
		}
	}
}


// EXE INS memory write analysis function 
void INS_MW_analysis(size_t mSize, ADDRINT targetAddr)
{
	set_mwblock(targetAddr);

	if (current_obf_fn == NULL) return;
	if (isDLLAnalysis && targetAddr >= main_img_saddr && targetAddr < main_img_eaddr) return;

	if (GetModuleInfo(targetAddr) != NULL) return;
	if (targetAddr >= main_img_saddr && targetAddr < main_txt_eaddr) return;

	for (size_t i = 0; i < mSize; i++)
	{
		obfaddr2fn[targetAddr + i] = current_obf_fn;
	}

#if DEBUG == 2
	*fout << "Write: " << toHex(targetAddr) << ' ' << *current_obf_fn << endl;
#endif
}

// EXE INS memory read analysis function 
void INS_MR_analysis(ADDRINT targetAddr)
{
	fn_info_t *finfo = GetFunctionInfo(targetAddr);
	if (finfo == NULL) return;
	current_obf_fn = finfo;
#if DEBUG == 2
	*fout << "API Read: " << toHex(targetAddr) << ' ' << *current_obf_fn << endl;
#endif
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
	*fout << toHex(addr) << ' ' << "T:" << threadid << " " << GetAddrInfo(addr) << endl;			
	PIN_ReleaseLock(&lock);	
}


// ========================================================================================================================
// Common Callbacks
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

				if (rtnname == ".text") continue;

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

		else if (SEC_Name(sec) == ".idata") 
		{
			obf_idata_saddr = SEC_Address(sec);
			obf_idata_eaddr = obf_idata_eaddr + SEC_Size(sec);
		}

	}

}

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
 * Internal Thread
 */
VOID unpack_thread(VOID *arg)
{	
	string msg_hdr = "Unpack Thread: ";

	// Wait until OEP is found.
	LOG(msg_hdr + "Waiting until OEP.\n");
	PIN_SemaphoreWait(&sem_oep_found);

	// Search for obfuscated API calls.
	LOG(msg_hdr + "Searching for obfuscated calls.\n");
	FindObfuscatedAPICalls();
#if LOG_CALL_CHECK == 1
	*fout << "# Obfuscated Call Candidates:" << endl;
	*fout << "# ------------------------------" << endl;
	for (auto e : obf_call_candidate_addrs) {
		*fout << "# " << e << endl;
	}
	*fout << endl;
#endif

	if (packer_type == "vmp" || (packer_type == "themida" && ADDRSIZE == 8)) {
		// Resolve obfuscated API calls for x64
		LOG(msg_hdr + "Resolving obfuscated API Calls.\n");
		current_resolve_api = 0;
		isCheckAPIStart = true;
		PIN_SemaphoreWait(&sem_resolve_api_end);
	}	

	// Search for IAT area.
	LOG(msg_hdr + "Searching for IAT Area.\n");
	bool isIAT = FindIATArea();
	if (!isIAT)
	{
		LOG(msg_hdr + "Cannot find an IAT are condidate in the binary.\n");
	}
	
	// api patch	
	LOG(msg_hdr + "Searching for an export area.\n");

	PrintIATArea();
/*
	if (ADDRSIZE == 4) {
		PrintIATArea_x86();
	}
	else {
		PrintIATArea_x64();
	}
	*/
	LOG(msg_hdr + "Fixing IAT.\n");
	FixIAT();
	LOG(msg_hdr + "Fixing obfuscated calls.\n");
	FixCall();

	PIN_SemaphoreSet(&sem_unpack_finished);
	LOG(msg_hdr + "Set sem_unpack_finished\n");

	PIN_SemaphoreSet(&sem_dump_finished);	

	((ofstream*)fout)->close();
	PIN_ExitProcess(-1);
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
    
	string outputFileName = KnobOutputFile.Value();	
	if (outputFileName == "result.txt")
	{
		outputFileName = string(argv[argc - 1]);
		outputFileName += ".txt";
	}		
	fout = new ofstream(outputFileName.c_str());	

	isMemDump = KnobDump.Value();

	packer_type = KnobPackerType.Value();
	*fout << "PACKER:" << packer_type << endl;
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
	if (packer_type == "vmp") {
		TRACE_AddInstrumentFunction(TRC_inst, 0);
	}
	else if (packer_type == "themida" || packer_type == "enigma") {
		if (ADDRSIZE == 4) INS_AddInstrumentFunction(INS_inst, 0);
		else if (ADDRSIZE == 8) TRACE_AddInstrumentFunction(TRC_inst, 0);
	}

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	
	// Initialize semaphore
	PIN_SemaphoreInit(&sem_oep_found);
	PIN_SemaphoreInit(&sem_resolve_api_end);
	PIN_SemaphoreInit(&sem_unpack_finished);
	PIN_SemaphoreInit(&sem_dump_finished);
	
	// Spawn an internal thread
	PIN_SpawnInternalThread(unpack_thread, NULL, 0, &unpack_thread_uid);

	// Start the program, never returns    
	PIN_StartProgram();
	
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
