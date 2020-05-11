#include "ThemidaPinAnalyzer.h"
namespace NW {
#include <Windows.h>
}
#include "ucrtdll.h"

using namespace std;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool", "o", "result.txt", "specify file name for the result");
KNOB<BOOL> KnobDump(KNOB_MODE_WRITEONCE, "pintool", "dump", "", "save memory dump");
KNOB<string> KnobDLLFile(KNOB_MODE_WRITEONCE, "pintool", "dll", "", "specify packed dll file");
KNOB<string> KnobPackerType(KNOB_MODE_WRITEONCE, "pintool", "packer", "themida", "packer type: tmd2, tmd3, vmp or enigma");
KNOB<BOOL> KnobDirectCall(KNOB_MODE_WRITEONCE, "pintool", "direct", "", "direct call");
KNOB<string> KnobIntermediateResultFile(KNOB_MODE_WRITEONCE, "pintool", "ir", "", "specify file name for storing intermediate result");


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

string print_regs(LEVEL_VM::CONTEXT* ctxt) 
{
	stringstream r;
	for (REG reg : regs_ctx) {
		r << REG_StringShort(reg) << ':' << toHex(PIN_GetContextReg(ctxt, reg)) << endl;
	}
	return r.str();
}


REG check_api_fn_assignment_to_register(LEVEL_VM::CONTEXT* ctxt)
{
	REG set_api_reg = REG_INVALID_;
	for (REG reg : regs_for_obfuscation) {
		ADDRINT reg_val = PIN_GetContextReg(ctxt, reg);
		fn_info_t* fn = GetFunctionInfo(reg_val);
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



// ========================================================================================================================
// API Detection Functions 
// ========================================================================================================================

/// Find obfuscated API jumps 
///
/// Pattern 1: API wrapping
/// call API_Jmp	E8 ...
/// ...
/// jmp API_Function	E9 ...   (jump relative. obfuscated)
/// <==
/// call API_Jmp	E8 ...
/// ...
/// jmp API_Function	FF 25 ...    (jmp indirect)
///
/// Pattern 2: Virtual Call
/// 
/// virtual_call_1: jmp API_Jmp		E9 __ __ __ __  (jump relative. obfuscated)
///                 db 0x__         __ (garbage byte)        
/// virtual_call_2: NOP; jmp API_Jmp    90 E9 ... (jump relative. obfuscated) 
/// ... 
/// offset virtual_call_1
/// offset virtual_call_2
/// ...
void FindObfuscatedAPIJumps() {
	// only 32bit
	if (ADDRSIZE == 8) return;

	size_t scan_area_size = main_txt_eaddr - main_txt_saddr;
	UINT8* buf = (UINT8*)malloc(scan_area_size);
	size_t idx, idx2;
	ADDRINT iat_start_addr = 0, iat_size = 0;

	sec_info_t* current_section = NULL, * target_section = NULL;

	unsigned char* pc = reinterpret_cast<unsigned char*>(main_txt_saddr);

	// buf has executable memory image
	EXCEPTION_INFO* pExinfo = NULL;

	size_t num_copied = PIN_SafeCopyEx(buf, pc, scan_area_size, pExinfo);

#if LOG_DUMP == 1
	*fout << "Searching for call to Obfuscated jmp and offset to Obfuscated jmp" << endl;
#endif

	// pattern 1: 
	// search for address modification in program
	ADDRINT call_src, call_dst, jmp_src, jmp_dst;
	size_t num_redirection; 
	size_t call_search_size;
	if (packer_type == "vmp") {
		call_search_size = imp_start_addr - main_txt_saddr;
	}
	else {
		call_search_size = num_copied;
	}

	for (idx = 0; idx < call_search_size - 6; idx++)
	{
		// check call to api jmp table
		if (buf[idx] == 0xE8) {			
			call_src = main_txt_saddr + idx;
			call_dst = call_src + 5 + TO_UINT32(buf + idx + 1);

			*fout << "# Call " << toHex(call_src) << "->" << toHex(call_dst) << endl;

			// check api jmp and wrapped api jmp
			if (call_dst > call_src && call_dst < main_txt_eaddr) {				
				idx2 = call_dst - main_txt_saddr;
				
				// jmp or NOP; jmp  
				// or  				
				// one more wrapping
				num_redirection = 0;
				while (buf[idx2] == 0xE9 || buf[idx2] == 0x90 && buf[idx2 + 1] == 0xE9) {
					num_redirection++;
					jmp_src = main_txt_saddr + idx2;
					if (buf[idx2] == 0xE9) {
						jmp_dst = jmp_src + 5 + TO_UINT32(buf + idx2 + 1);
					}
					else {
						jmp_dst = jmp_src + 6 + TO_UINT32(buf + idx2 + 2);
					}
#if LOG_DUMP == 1
					*fout << "# Jmp " << toHex(jmp_src) << "->" << toHex(jmp_dst) << endl;
#endif

					// one more wrapping
					if (jmp_dst > jmp_src && jmp_dst < main_txt_eaddr) {
						idx2 = jmp_dst - main_txt_saddr;
						continue;
					}

					break;
				}

				if (num_redirection >= 1 && num_redirection <= 2) {
					// check api for themida redirection
					fn_info_t* fn = GetFunctionInfo(jmp_dst);
					if (fn == NULL) {
						auto it = obfaddr2fn.find(jmp_dst);
						if (it == obfaddr2fn.end()) continue;
						fn = it->second;
					}					
					// add_obfuscated_call_candidates(jmp_src, fn->saddr, INDIRECT_JMP, "", 0);
					obf_calls.push_back(obf_call_t(jmp_src, fn->saddr, 0, INDIRECT_JMP, "", 0));
				}
			}
		}
	}

	// pattern 2:
	// search for obfuscated virtual table
	// search after IAT 
	*fout << "# IAT end " << toHex(imp_end_addr) << endl;
	
	for (idx = Align(imp_end_addr - main_txt_saddr, 4); idx < num_copied - 6; idx+=4)
	{
		// check offset
		ADDRINT offset = TO_UINT32(buf + idx);
		if (offset >= main_txt_saddr && offset < imp_start_addr) {
			// check api jmp
			*fout << "# Offset " << toHex(main_txt_saddr + idx) << ' ' << toHex(offset) << endl;
			idx2 = offset - main_txt_saddr;
			// jmp or NOP; jmp 				
			if (buf[idx2] == 0xE9) {
				jmp_dst = offset + 5 + TO_UINT32(buf + idx2 + 1);
			}
			else if (buf[idx2] == 0x90 && buf[idx2+1] == 0xE9) {
				jmp_dst = offset + 6 + TO_UINT32(buf + idx2 + 2);
			}
			else continue;

			// check api
			fn_info_t* fn = GetFunctionInfo(jmp_dst);
			if (fn == NULL) {
				auto it = obfaddr2fn.find(jmp_dst);
				if (it == obfaddr2fn.end()) continue;
				fn = it->second;
			}
			jmp_src = offset;
			// add_obfuscated_call_candidates(jmp_src, fn->saddr, INDIRECT_JMP, "", 0);
			obf_calls.push_back(obf_call_t(jmp_src, fn->saddr, 0, INDIRECT_JMP, "", 0));
		}
	}
}

/// Find obfuscated API Calls
void FindObfuscatedAPICalls()
{	
	size_t text_section_size = main_txt_eaddr - main_txt_saddr;
	size_t imp_section_size = imp_end_addr - imp_start_addr;

	UINT8 *buff_text_section = (UINT8*)malloc(text_section_size);
	UINT8* buff_imp_section = (UINT8*)malloc(imp_section_size);
	size_t idx, idx2;
	ADDRINT addr, addr2, target_addr;	
	
	sec_info_t *current_section = NULL, *target_section = NULL;	
	
	unsigned char* p_text_section = reinterpret_cast<unsigned char*>(main_txt_saddr);
	unsigned char* p_imp_section = reinterpret_cast<unsigned char*>(imp_start_addr);

	// buf has executable memory image
	EXCEPTION_INFO *pExinfo = NULL;

	size_t text_section_copied = PIN_SafeCopyEx(buff_text_section, p_text_section, text_section_size, pExinfo);
	size_t imp_section_copied = PIN_SafeCopyEx(buff_imp_section, p_imp_section, imp_section_size, pExinfo);

	// search for address modification in program

#if LOG_DUMP == 1
	*fout << "# Searching for Obfuscated Calls" << endl;
#endif

	FindObfuscatedAPIJumps();

	if (packer_type == "tmd2" || packer_type == "tmd3" || packer_type == "enigma") 
	{
		for (idx = 0; idx < text_section_copied - 6; idx++)
		{
			addr = main_txt_saddr + idx;
			if (ADDRSIZE == 4 && packer_type == "tmd2")
			{
				// Themida x86 2.x
				// --------------
				// CALL r/m32 (FF 1F __ __ __ __)
				// is patched by Themida into
				// CALL rel32; NOP (E8 __ __ __ __ 90)
				// CALL rel32; NOP (90 E8 __ __ __ __)

				obf_call_t obf_call;
				
				// *fout << toHex(main_txt_saddr + idx) << endl;
				if (buff_text_section[idx] == 0xE8) {

					if (buff_text_section[idx + 5] == 0x90) obf_call.n_prev_pad_byts = 0;
					else if (buff_text_section[idx -1] == 0x90) obf_call.n_prev_pad_byts = 1;
					else continue;
					obf_call.ins_type = INDIRECT_CALL;
				}
				else if (buff_text_section[idx] == 0xE9) {
					
					if (buff_text_section[idx - 1] == 0x90) obf_call.n_prev_pad_byts = 1;
					else obf_call.n_prev_pad_byts = 0;
					// else if (bufp[5] == 0x90) obf_call.n_prev_pad_byts = 0;
					// jmp api. not accurate heuristics. only seh
					// else if (bufp[6] == 0xcc && bufp[7] == 0xcc && bufp[8] == 0xcc && bufp[9] == 0xcc) obf_call.n_prev_pad_byts = 0;
					// else continue;
					obf_call.ins_type = INDIRECT_JMP;
				}
				else continue;

				obf_call.src = main_txt_saddr + idx - obf_call.n_prev_pad_byts;
				obf_call.dst = obf_call.src + 6 + TO_UINT32(buff_text_section + idx + 1);

#if LOG_DUMP == 1
				*fout << "# " << toHex(obf_call.src) << ' ' << toHex(obf_call.dst) << endl;
#endif

				fn_info_t* fn;
				fn = GetFunctionInfo(obf_call.dst);
				if (fn == NULL) {
					if (obfaddr2fn.find(obf_call.dst) == obfaddr2fn.end())
						continue;
					fn = obfaddr2fn[obf_call.dst];
				}
				//			
				//string modstr = fn->module_name;
				//string fnstr = fn->name;
				//string reladdr = toHex(obf_call.src - main_img_saddr);
				//*fout << reladdr << '\t' << obf_call.get_mnem() << '\t' << modstr << '\t' << fnstr << endl;

				obf_call.dst = fn->saddr;								
				obf_calls.push_back(obf_call);

			}
			if (ADDRSIZE == 4 && packer_type == "enigma") {		
				// Enigma Protector x86
				// ---------------------
				// Enigma Protector preserve CALL r/m32
				// CALL [addr] (FF 15 __ __ __ __)
				// But the address points to allocated memory area
				// where the API function is copied into. 
				if (buff_text_section[idx] == 0xFF && buff_text_section[idx + 1] == 0x15)
				{
					// addr: current address
					// addr2: redirection address in bracket
					// target_addr: real API address
					sec_info_t *tmp_sec = GetSectionInfo(addr);

					if (current_section == NULL) {
						current_section = tmp_sec;
					}
					else if (current_section != tmp_sec) {
						break;
					}

					addr2 = TO_ADDRINT(buff_text_section + idx + 2);
					// *fout << toHex(addr) << " call [" << toHex(addr2) << ']' << endl;
					idx2 = addr2 - main_txt_saddr;

					// skip malformed address
					// address should be inside the image
					if (idx2 > text_section_size) continue;
					
					target_addr = TO_ADDRINT(buff_text_section + idx2);

					// *fout << '[' << toHex(addr2) << "]=" << toHex(target_addr);

					if (obfaddr2fn.find(target_addr) != obfaddr2fn.end())
					{
						fn_info_t *fn = obfaddr2fn[target_addr];

						string modstr = fn->module_name;
						string fnstr = fn->name;
						string reladdr = toHex(addr - main_img_saddr);
						// *fout << reladdr << "\tcall " << modstr << '\t' << fnstr << endl;
						// add_obfuscated_call_candidates(addr, target_addr, INDIRECT_CALL, "", 0);	
						obf_calls.push_back(obf_call_t(addr, target_addr, 0, INDIRECT_CALL, "", 0));
					}
				}
			}

			else if (ADDRSIZE == 8)
			{
				// CALL r/m32 (FF 1F __ __ __ __)
				// is patched by Themida64 into
				// CALL rel32; db 00 (E8 __ __ __ __ ; 00)
				if (buff_text_section[idx] == 0xE8 && (buff_text_section[idx + 5] == 0x00 || buff_text_section[idx + 5] == 0x90))
				{
					addr = main_txt_saddr + idx;
					target_addr = addr + 5 + TO_UINT32(buff_text_section + idx + 1);
					current_section = GetSectionInfo(addr);
					target_section = GetSectionInfo(target_addr);
					if (current_section == NULL || target_section == NULL) continue;
					// obfuscated call target is selected by 
					// - call targets into other section of the main executables				

					if (current_section->module_name == target_section->module_name &&
						current_section->saddr != target_section->saddr) {
						if (check_disasm(target_addr) != 0) {
							//add_obfuscated_call_candidates(addr, target_addr, INDIRECT_CALL, "", false);
							obf_call_candidates.push_back(obf_call_t(addr, target_addr, 0, INDIRECT_CALL, "", false));
						}
					}
				}
			}
		}
	}
	else if (packer_type == "vmp")
	{
		for (idx = 0; idx < text_section_copied - 6; idx++)
		{
			// CALL r/m32 (FF 1F __ __ __ __)
			// is patched by VMProtect into
			// CALL rel32; ?? (E8 __ __ __ __ ; ??)
			if (buff_text_section[idx] == 0xE8)
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

				// check rex.w before & int 3 after
				if (ADDRSIZE == 8 && buff_text_section[idx - 1] == 0x48 && buff_text_section[idx +5] != 0xcc) {
					has_rexw = true;
				}


				// push reg at caller_addr : PATTERN 1-1, 2-1, 3-1
				if (buff_text_section[idx - 1] >= 0x50 && buff_text_section[idx - 1] <= 0x57) {
					pattern_before_push_reg = 1;
					// sometimes vmprotect add rex.w prefix
					if (ADDRSIZE == 8 && buff_text_section[idx - 2] == 0x48) {						
						pattern_before_push_reg++;
					}						
				}

				target_addr = addr + 5 + buff_text_section[idx + 1] + (buff_text_section[idx + 2] << 8) + (buff_text_section[idx + 3] << 16) + (buff_text_section[idx + 4] << 24);

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
					// add_obfuscated_call_candidates(addr, target_addr, INDIRECT_CALL, "", pattern_before_push_reg);
					obf_call_candidates.push_back(obf_call_t(addr, target_addr, 0, INDIRECT_CALL, "", pattern_before_push_reg));
				}
			}
		}
	}

	free(buff_text_section);
	free(buff_imp_section);
}


bool FindIATAtSecondSection() {	
	size_t imp_size;
	if (packer_type == "vmp") {
		imp_start_addr = obf_rdata_saddr;
		imp_end_addr = obf_rdata_eaddr;
	}
	else if (packer_type == "tmd3") {
		auto sec = main_img_info->sec_infos.at(1);
		imp_start_addr = sec->saddr;
		imp_end_addr = sec->eaddr;
	}
	
	*fout << "# IMP Start: " << toHex(imp_start_addr) << " IMP End: " << toHex(imp_end_addr) << endl;

	imp_size = imp_end_addr - imp_start_addr;
	UINT8* buf = (UINT8*)malloc(imp_size);
	// buf has executable memory image
	PIN_SafeCopy(buf, (VOID*)imp_start_addr, imp_size);

	// Check imports of vmp	
	ADDRINT iat_addr, i;
	ADDRINT iat_data, iat_data_prev, iat_data_next;

	imp_list.clear();

	// Find IAT End Address	
	iat_data_prev = 0;
	for (i = 0; i < imp_size - ADDRSIZE; i += ADDRSIZE) {		
		iat_data = TO_ADDRINT(buf + i);
		iat_addr = imp_start_addr + i;
		// Entry Address is a mark for end of import address table
		if (iat_data_prev == 0 && IS_TEXT_SEC(iat_data)) {
			break;
		}
		iat_data_prev = iat_data;
	}
	imp_end_addr = iat_addr;

	iat_data = 0;
	iat_data_next = TO_ADDRINT(buf);
	for (i = 0; i < imp_end_addr - imp_start_addr - ADDRSIZE; i += ADDRSIZE) {				
		// end mark: 0 ; entry address (nullsub) ; 0
		iat_data_prev = iat_data;
		iat_data = iat_data_next;
		iat_data_next = TO_ADDRINT(buf + i + ADDRSIZE);

		iat_addr = imp_start_addr + i;								
		// *fout << "# " << toHex(iat_addr) << ' ' << toHex(iat_data) << endl;
		
		// Themida 3.x: IAT elements are obfuscated. 
		// obf_imports are after deobfuscated by run-until-API
		if (iat_data > imp_end_addr && iat_data < main_img_eaddr) {
			*fout << "# " << toHex(iat_addr) << ' ' << toHex(iat_data) << endl;
			if (check_disasm(iat_data) != 0) {
				obf_call_t obfcall = obf_call_t(0, iat_data, iat_addr, INDIRECT_CALL, "", 0);
				obf_call_candidates.push_back(obfcall);
				*fout << "# Obfuscated IAT: " << obfcall << endl;
			}			
		}

		auto fn = GetFunctionInfo(iat_data);
		if (iat_data == 0 || fn == NULL) {
			imp_list.push_back({ iat_addr, 0, "", "" });				
		}		
		else {
			auto mf = ResolveForwardedFunc(fn->module_name, fn->name);
			fn->name = mf.fn;
			fn->module_name = mf.dll;
			imp_list.push_back({ iat_addr, fn->saddr, fn->name, fn->module_name });
		}			
	}
	iat_addr += ADDRSIZE;
	imp_list.push_back({ iat_addr, 0, "", "" });
	imp_end_addr = iat_addr;
	found_IAT = true;
	free(buf);	
	return found_IAT;
}


bool FindIAT()
{
	if (packer_type == "vmp" || packer_type == "tmd3")
	{
		return FindIATAtSecondSection();
	}

	size_t txtsize = main_txt_eaddr - main_txt_saddr;
	if (packer_type == "enigma")
	{
		txtsize += 0x1000;
	}
	

	*fout << "txtsize:" << toHex(txtsize) << endl;
	UINT8 *buf = (UINT8*)malloc(txtsize);
	// buf has executable memory image
	PIN_SafeCopy(buf, (VOID*)main_txt_saddr, txtsize);


#if LOG_OBFUSCATED_CALLS == 2
	ADDRINT a0 = main_txt_saddr;
	size_t cnt = 0;
	for (UINT8* bufp = buf; bufp < buf + txtsize; bufp+= ADDRSIZE, a0+=ADDRSIZE) {
		if (cnt % 16 == 0) *fout << "# " << toHex(a0) << ' ';
		*fout << toHex(TO_ADDRINT(bufp)) << ' ';
		if (cnt++ % 16 == 15) *fout << endl;
	}
	*fout << endl;
	for (auto it : obfaddr2fn) {
		*fout << "# " << toHex(it.first) << ' ' << *it.second << endl;
	}
	*fout << endl;
#endif

	// Search for Imports
	size_t num_imp_fn = 0;
	size_t num_consecutive_not_imp_fn = 0;
	UINT8 *bufp;
	ADDRINT iat_data, iat_addr, i;
	mod_info_t *mod;
	// for (size_t blk = 0x1000; blk < txtsize; blk += 0x1000) {		
	for (size_t blk = 0x1042000; blk < txtsize; blk += 0x1000) {
		imp_list.clear();	

#if LOG_OBFUSCATED_CALLS == 1
		*fout << "## Searching in " << toHex(main_txt_saddr + blk) << endl;
#endif

		for (i = 0xb64; i < 0x1000; i += ADDRSIZE) {
#if LOG_OBFUSCATED_CALLS == 1
			* fout << "## i=" << toHex(i) << endl;
#endif

			bufp = buf + blk + i;
			iat_addr = main_txt_saddr + blk + i;
			iat_data = TO_ADDRINT(bufp);	
#if LOG_OBFUSCATED_CALLS == 1
			*fout << "## " << toHex(iat_addr) << ' ' << toHex(iat_data) << endl;
#endif

			// Entry Address is a mark for end of import address table
			if (IS_TEXT_SEC(iat_data)) {
				*fout << "## End Mark\n";
				*fout << "a00\n";
				fout->flush();
				break;
			}

#if TARGET_IA32
			auto it = obfaddr2fn.find(iat_data);

			// if target_addr is obfuscated function address
			if (it != obfaddr2fn.end())
			{
#if LOG_OBFUSCATED_CALLS == 1
				*fout << "## IAT ENTRY: ";
#endif
				auto fn = it->second;
				if (fn == NULL) {
					*fout << "# NO FUNCTION\n";
					break;
				}
				addr2fnaddr[iat_data] = fn->saddr;	// here
				auto mf = ResolveForwardedFunc(fn->module_name, fn->name);
				fn->name = mf.fn;
				fn->module_name = mf.dll;
				imp_list.push_back({ iat_addr, fn->saddr, fn->name, fn->module_name });
				num_consecutive_not_imp_fn = 0;
				num_imp_fn++;

#if LOG_OBFUSCATED_CALLS == 1
				*fout << toHex(iat_addr) << ' ' << *it->second << endl;
#endif
				continue;
			}
#endif
			* fout << "## not obfuscated function\n";

			mod = GetModuleInfo(iat_data);		
			if (iat_data == 0 || mod == NULL) {
				if (mod == NULL) *fout << "## no mod info\n";
				if (++num_consecutive_not_imp_fn > 1) {
					*fout << "## no not imp fn " << num_consecutive_not_imp_fn << endl;
					*fout << "a06\n";
					fout->flush();

					break;
				}
				imp_list.push_back({ iat_addr, 0, "", "" });
				continue;
			}

			num_consecutive_not_imp_fn = 0;
			num_imp_fn++;
			*fout << "a01\n";
			fout->flush();

			auto fn = GetFunctionInfo(iat_data);
			if (fn == NULL) {
				*fout << "# NO FUNCTION\n";
			}
			else {
				*fout << fn->module_name << ' ' << fn->name << endl;
			}
			*fout << "a02\n";
			
			fout->flush();

			auto mf = ResolveForwardedFunc(fn->module_name, fn->name);
			*fout << "a03\n";
			fout->flush();

			fn->name = mf.fn;
			fn->module_name = mf.dll;
			imp_list.push_back({ iat_addr, fn->saddr, fn->name, fn->module_name });
		}

		if (num_imp_fn > 3) {	// assumption: at least 3 import function
#if LOG_OBFUSCATED_CALLS == 1
			* fout << "Found " << num_imp_fn << " imported function\n";
#endif
			imp_start_addr = main_txt_saddr + blk;
			imp_end_addr = main_txt_saddr + blk + i;
			found_IAT = true;
			goto free_buf;
		}
	}

#if LOG_OBFUSCATED_CALLS == 1
	* fout << "# SEARCH IAT ENDED\n";
#endif
	// find zero block with interval 0x1000
	if (imp_start_addr != 0) goto free_buf;
	imp_start_addr = 0;
		
	for (size_t blk = 0; blk + obf_call_candidates.size() * ADDRSIZE < txtsize; blk += 0x1000) {
		found_zero_blk = true;
		for (size_t i = 0; i < obf_call_candidates.size() * ADDRSIZE; i++) {
			if (buf[blk + i] != 0) {
				found_zero_blk = false;
				break;
			}
		}
		if (found_zero_blk) {
			imp_start_addr = main_txt_saddr + blk;
			*fout << "# iat candidate:" << toHex(imp_start_addr) << endl;
			goto free_buf;
		}
	}
	
	// find zero block with interval 0x100
	*fout << "# 2" << endl;
	for (size_t blk = 0; blk + obf_call_candidates.size() * ADDRSIZE < txtsize; blk += 0x100) {
		found_zero_blk = true;
		for (size_t i = 0; i < obf_call_candidates.size() * ADDRSIZE; i++) {
			if (buf[blk + i] != 0) {
				found_zero_blk = false;
				break;
			}
		}
		if (found_zero_blk) {
			imp_start_addr = main_txt_saddr + blk;
			*fout << "# iat candidate:" << toHex(imp_start_addr) << endl;
			goto free_buf;
		}
	}
	
	// If there is no concave, select idata 
	*fout << "# 3" << endl;	
	imp_start_addr = obf_idata_saddr;
	*fout << "# iat candidate:" << toHex(imp_start_addr) << endl;

free_buf:
	free(buf);

	// If IAT area is not found, make a new IAT area in the gap
	if (!found_IAT) {
		imp_list.clear();
		// Build sorted_api_map to gather functions per dll: function name -> fninfo. 
		map<string, fn_info_t*> sorted_api_map;
		for (auto it = obfaddr2fn.begin(); it != obfaddr2fn.end(); it++) {
			fn_info_t* fninfo = it->second;
			string key = fninfo->module_name + '.' + fninfo->name;
			sorted_api_map[key] = fninfo;
		}

		// Resolve obfuscated API call
		ADDRINT current_addr = imp_start_addr;
		ADDRINT rel_addr = 0;

		string prev_mod_name = "";
		for (auto it = sorted_api_map.begin(); it != sorted_api_map.end(); it++, current_addr += ADDRSIZE) {
			// assign resolved function address to candidate IAT area
			fn_info_t* fn = it->second;
			if (prev_mod_name != "" && prev_mod_name != fn->module_name) {
				imp_list.push_back({ iat_addr, 0, "", "" });
			}
			imp_list.push_back({ iat_addr, fn->saddr, fn->name, fn->module_name });
			prev_mod_name = fn->module_name;
		}
		imp_list.push_back({ iat_addr, 0, "", "" });
	}

	// *fout << toHex(addrZeroBlk) << endl;
	return found_IAT;
}


// reconstruct import list by resolved obfuscated calls
void ReconstructImpList() {

	*fout << "# Obfuscated Calls" << endl;	

	// Build sorted_api_map to gather functions per dll: function name -> fninfo. 
	map<string, fn_info_t*> sorted_api_map;

	for (auto &e : obf_calls) {
		*fout << "# " << e << endl;
		fn_info_t* fn = GetFunctionInfo(e.dst);		
		string m, f;
		m = fn->module_name;
		f = fn->name;		

		auto n = ResolveForwardedFunc(fn->module_name, fn->name);
		fn->module_name = n.dll;
		fn->name = n.fn;

		if (m != fn->module_name || f != fn->name) {
			*fout << "# " << fn->module_name << "." << fn->name << endl;
		}

		string key = fn->module_name + '.' + fn->name;
		sorted_api_map[key] = fn;
	}	

	// Resolve obfuscated API call
	ADDRINT iat_addr = imp_start_addr;
	size_t i = 0;
	ADDRINT rel_addr = 0;
	string prev_mod_name = "";
	fn_info_t* fn;

	for (auto e : sorted_api_map) {
		fn = e.second;	
		if (prev_mod_name != "" && fn->module_name != prev_mod_name) {
			imp_list[i] = { iat_addr, 0, "", "" };
			i++;
			iat_addr += ADDRSIZE;
		}
		imp_list[i] = {
			iat_addr,
			fn->saddr, 
			fn->name,
			fn->module_name
		};		
		i++;
		iat_addr += ADDRSIZE;
		
		prev_mod_name = fn->module_name;
	}
	imp_list[i] = { iat_addr, 0, "", "" };
}


// Check External Reference from main image address
void PrintIATArea()
{
	// print IAT info
	*fout << "IAT START: " << toHex(imp_start_addr - main_img_saddr) << endl;
	ADDRINT addr;
	for (auto e : imp_list) {		
		addr = e.addr;
		if (e.func_addr != 0) {
			*fout << toHex(addr - main_img_saddr) << "\taddr\t" << e.dll_name << '\t' << e.func_name << endl;
		}
		else {
			*fout << toHex(addr - main_img_saddr) << "\taddr\t0\t0" << endl;
		}
	}
	*fout << "IAT SIZE: " << toHex((imp_end_addr - imp_start_addr) / ADDRSIZE + 1) << endl;
}


// API Detect executable trace analysis function
void TRC_analysis(CONTEXT *ctxt, ADDRINT addr, bool is_ret, THREADID threadid)
{	

	if (threadid != 0) return;
	
#if LOG_TRACE == 1
	if (IS_MAIN_IMG(addr)) {
		*fout << "Trace:" << toHex(addr) << endl;
	}
#endif

	// Check OEP
	if (oep == 0)
	{
		// common for dll and exe
		set_meblock(addr);
		if (IS_TEXT_SEC(addr))
		{
			// vmp supports no packing. 20.5.4.
			if (get_mwblock(addr) && get_meblock(addr) > 0 && !is_ret || packer_type == "vmp")
			{
				if (packer_type == "enigma") {
					UINT8 buf[6];
					PIN_SafeCopy(buf, (VOID*)addr, 6);
					if (buf[0] == 0xEB && buf[1] == 0x03 && buf[5] == 0xC3) {
						*fout << "# Fake OEP: ";
						for (auto pt : buf)
							*fout << toHex1(pt) << ' ';
						return;
					}
				}
				oep = addr - main_img_saddr;
				*fout << "OEP:" << toHex(oep) << endl;
				PIN_SaveContext(ctxt, &ctx0);
				PIN_SemaphoreSet(&sem_oep_found);
			}
			
			
			return;

		}

		// if some problem occurs in dll
		if (isDLLAnalysis && dll_is_unpack_started) {
			if (addr >= loader_saddr && addr < loader_eaddr) {
				// set fake oep
				oep = main_txt_saddr - main_img_saddr;
				*fout << "OEP:" << toHex(oep) << endl;
				PIN_SaveContext(ctxt, &ctx0);
				PIN_SemaphoreSet(&sem_oep_found);
			}
		}
	}
	else if (skip_until_oep) {
		if (addr == oep + main_img_saddr) {
			*fout << "OEP:" << toHex(oep) << endl;
			skip_until_oep = false;
			PIN_SaveContext(ctxt, &ctx0);
			PIN_SemaphoreSet(&sem_oep_found);			
		}
		return;
		
	}
	if (isCheckAPIRunning) {
		// if obfuscated API checking is started and 
		// if the trace is in another section
		// then here is the obfuscated instructions that resolve 'call API_function'
		// These obfuscated instructions end by 'RET' instruction 
		// that jumps into API function code

		ADDRINT caller_addr = current_obfuscated_call->src;
		ADDRINT prev_addr = 0;

		UINT8 buf[8];		
		ADDRINT stkptr = PIN_GetContextReg(ctxt, REG_STACK_PTR);		
		PIN_SafeCopy(buf, (VOID*)stkptr, ADDRSIZE);

		traceAddrSeq.push_back(addr);
		traceSPSeq.push_back(stkptr);

#if LOG_CALL_CHECK == 1
		*fout << "#! CheckAPI running " << toHex(addr) << ' ' << GetAddrInfo(addr) << " # " << traceAddrSeq.size() << endl;
		fout->flush();
#endif

		fn_info_t* fninfo;

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
			if (set_api_reg != REG_INVALID_)
			{
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

				*fout << "# " << toHex(adjusted_caller_addr - main_img_saddr) << "\tmov-" << REG_StringShort(set_api_reg) << '\t' << fninfo->module_name << '\t' << fninfo->name << endl;
				obfaddr2fn[current_obf_fn_addr] = fninfo;
				mov_obfaddr2fn[current_obf_fn_addr] = fninfo;
				obf_calls.push_back(obf_call_t(adjusted_caller_addr, fninfo->saddr, 0, INDIRECT_MOV, REG_StringShort(set_api_reg), 0));
			}
			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			goto check_api_start;
		}

		// because some text section has some illegal instructions
		// skip ip is at .text after the first call
		if (traceAddrSeq.size() > 1 && IS_TEXT_SEC(addr) && !is_ret) {
			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			goto check_api_start;
		}

		if (traceAddrSeq.size() > 100)
		{
			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			goto check_api_start;
		}

		if (IS_MAIN_IMG(addr)) {
			// DO NOTHING
			return;
		}

		// if the trace in in API function
		// then here is the API function. 
		// Check the stack top value whether the value is next address of the call instruction. 
				
		fninfo = GetFunctionInfo(addr);

		if (fninfo == NULL) return;
		
		// skip user exception by false positive find api calls
		if (fninfo->name.find("KiUserExceptionDispatcher") != string::npos)
		{
			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			goto check_api_start;
		}

		if (packer_type == "tmd2" || packer_type == "tmd3" || packer_type == "enigma")
		{
			obf_call_type_e ty;
			if (TO_ADDRINT(buf) == current_caller_nextaddr) {
				ty = INDIRECT_CALL;
			}
			else {
				ty = INDIRECT_JMP;
			}

			*fout << "# --- " << fninfo->module_name << '\t' << fninfo->name << endl;
			obfaddr2fn[current_obf_fn_addr] = fninfo;
			*fout << "# --- " << toHex(current_caller_addr) << "->" << toHex(addr) << ' ' << ty << endl;			
			auto obf_call = obf_call_t(current_caller_addr, fninfo->saddr, current_obfuscated_call->indaddr, ty, "", 0);
			*fout << "# " << obf_call << endl;
			obf_calls.push_back(obf_call);
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
			obf_call_type_e ty;

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
				ty = INDIRECT_CALL;
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
				ty = INDIRECT_JMP;
				if (stk_diff == 0)
				{
					adjusted_caller_addr = caller_addr;
				}
				else if (stk_diff == -ADDRSIZE)
				{
					adjusted_caller_addr = caller_addr - current_obfuscated_call->n_prev_pad_byts;
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
			if (addr != fninfo->saddr) *fout << "branch into the middle of API function" << endl;
#endif

			*fout << "# " << toHex(adjusted_caller_addr - main_img_saddr) << '\t' << call_type << '\t' << fninfo->module_name << '\t' << fninfo->name << endl;
			// add_obfuscated_call_candidates(adjusted_caller_addr, addr, ty, "", 0);
			obf_calls.push_back(obf_call_t(adjusted_caller_addr, fninfo->saddr, 0, ty, "", 0));	
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
		if (current_obf_fn_pos == obf_call_candidates.size()) {
			// when checking obfuscated call finished, prepare the end 
			isCheckAPIStart = false;
			isCheckAPIEnd = true;
#if LOG_CALL_CHECK == 1
			*fout << "# Checking End " << current_obf_fn_pos << endl;
#endif
			goto check_api_end;
		}
		obf_call_t* obf_call;
		ADDRINT caller_addr, obfuscated_fn_addr, next_addr;
		obf_call = &obf_call_candidates.at(current_obf_fn_pos++);
		caller_addr = obf_call->src;
		obfuscated_fn_addr = obf_call->dst;
		
		current_caller_addr = caller_addr;
		current_caller_nextaddr = caller_addr + 6;
		current_obfuscated_call = obf_call;
		current_obf_fn_addr = obfuscated_fn_addr;
		
		traceAddrSeq.clear();
		traceSPSeq.clear();
		movRegApiFnAddrs.clear();

		// obfuscated call from text section
		if (caller_addr != 0) {			
			// next address is caller
			// to check mov reg, ...
			next_addr = caller_addr;
#if LOG_CALL_CHECK == 1
			* fout << "# Checking Obfuscated Call: " << toHex(obf_call->src) << ' ' << current_obf_fn_pos << '/' << obf_call_candidates.size() << endl;
#endif		
			//if (current_obf_fn_pos == 577 || 
			//	current_obf_fn_pos == 627 || 
			//	current_obf_fn_pos == 628 || 
			//	current_obf_fn_pos == 993) goto check_api_start;
			// currently call instruction is of the form 'E8 __ __ __ __' which is 5 bytes
			// but originally it is 'FF 15 __ __ __ __' or 'FF 25 __ __ __ __' which is 6 bytes
			// so next instruction address is addr + 6			
		}
		else {
			next_addr = obf_call->dst;
#if LOG_CALL_CHECK == 1
			* fout << "# Checking Obfuscated IAT Element: " << toHex(obf_call->indaddr) << "->" << toHex(next_addr) << ' ' 
				 << current_obf_fn_pos << '/' << obf_call_candidates.size() << endl;
#endif
		}
		
		isCheckAPIStart = false;
		isCheckAPIRunning = true;

		PIN_SetContextReg(ctxt, REG_INST_PTR, next_addr);
		PIN_ExecuteAt(ctxt);

	}

check_api_end:
	if (isCheckAPIEnd) {
		// after checking obfuscated calls, terminate.
		LOG("API Checking End\n");
		PIN_SemaphoreSet(&sem_resolve_api_end);
		PIN_SemaphoreWait(&sem_dump_finished);
		((ofstream*)fout)->close();
		PIN_ExitProcess(-1);
		return;
	}
}

// API Detect executable trace instrumentation function
void TRC_inst(TRACE trace, void *v)
{	
	ADDRINT addr = TRACE_Address(trace);

	bool is_ret = INS_IsRet(BBL_InsHead(TRACE_BblHead(trace)));
	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)TRC_analysis,
		IARG_CONTEXT,
		IARG_ADDRINT, addr,
		IARG_BOOL, is_ret,
		IARG_THREAD_ID,
		IARG_END);

	trace_cache_m[addr] = new vector<ADDRINT>;
	trace_next_addr_m[addr] = addr + TRACE_Size(trace);
	
	if (isDLLAnalysis)
	{
		if (addr == obf_dll_entry_addr) {
			dll_is_unpack_started = true;
			LOG("Unpack Started.\n");
		}
		if (!dll_is_unpack_started) return;
	}

	if (!IS_MAIN_IMG(addr)) return;

	//// check invalid instructions
	//if (isCheckAPIStart) {
	//	if (check_disasm2(addr) == 0) {
	//		*fout << "invalid disassembly" << endl;
	//		isCheckAPIStart = true;
	//		isCheckAPIRunning = false;
	//	}
	//}

	// instrument each memory read/write instruction
	// and
	// check unsupported instructions
	if (!skip_until_oep) {
		BBL bbl;
		INS ins, prev_ins;
		for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
			for (ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				prev_ins = ins;
				if (INS_IsFarRet(ins))
				{
					isCheckAPIStart = true;
					isCheckAPIRunning = false;
					*fout << "# Far Ret !!!" << endl;
				}
				if (INS_Mnemonic(ins) == "XRSTOR") continue;

				if (packer_type == "tmd2") {

					UINT32 memOperands = INS_MemoryOperandCount(ins);
					bool is_mem_write = false, is_mem_read = false;
					if (INS_Mnemonic(ins) == "XRSTOR") continue;

					for (size_t memOp = 0; memOp < memOperands; memOp++)
					{
						// Check each memory operand					
						if (INS_MemoryOperandIsRead(ins, memOp) && !INS_IsStackRead(ins))
						{
							is_mem_read = true;

						}
						if (INS_MemoryOperandIsWritten(ins, memOp) && !INS_IsStackWrite(ins))
						{
							is_mem_write = true;
						}
					}
					if (is_mem_read) {
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)INS_MR_analysis,
							IARG_MEMORYREAD_EA,
							IARG_END);
					}
					if (is_mem_write) {
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)INS_MW_analysis,
							IARG_INST_PTR,
							IARG_MEMORYWRITE_SIZE,
							IARG_MEMORYWRITE_EA,
							IARG_END);
					}
				}
				else {
					if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins))
					{
						// record write addresses to detect OEP
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)INS_MW_analysis,
							IARG_INST_PTR,
							IARG_MEMORYWRITE_SIZE,
							IARG_MEMORYWRITE_EA,
							IARG_END);
					}
				}
			}
		}

	}


	// check last ins
	INS last_ins = BBL_InsTail(TRACE_BblTail(trace));
	string mne = INS_Mnemonic(last_ins);
	if (oep) {		
		if (!INS_IsControlFlow(last_ins) &&
			!INS_Stutters(last_ins) &&
			mne != "CPUID" &&
			mne != "INT" &&
			mne != "POPFD"
			) {
			isCheckAPIStart = true;
			isCheckAPIRunning = false;
			return;
		}
	}	

	if (isCheckAPIRunning && INS_IsCall(last_ins)) {
		string asmcode = INS_Disassemble(last_ins);
		// *fout << asmcode << endl;
		auto pos = asmcode.rfind(' ');
		if (pos + 3 < asmcode.length()) {
			istringstream ss(&asmcode[pos + 3]);
			ADDRINT tgt;
			ss >> hex >> tgt;
			// *fout << toHex(tgt) << endl;
			auto info = GetModuleInfo(tgt);
			if (info == NULL) {
				*fout << "skip" << endl;
				isCheckAPIStart = true;
				isCheckAPIRunning = false;
				return;
			}
		}
	}
}


// ========================================================================================================================
// API Detection Functions for x86
// ========================================================================================================================

// Memory Protection Fix
void FixMemoryProtection()
{
	OS_RETURN_CODE rc;
	NATIVE_PID pid;
	rc = OS_GetPid(&pid);
	*fout << "# Fixing Memory Protection PID: " << pid << endl;
	
	OS_MEMORY_AT_ADDR_INFORMATION info;
	
	for (auto sec : main_img_info->sec_infos) {

		OS_QueryMemory(pid, (VOID*)sec->saddr, &info); 
		*fout << "# ADDR:" << toHex((ADDRINT)info.BaseAddress) << endl;
		*fout << "# SIZE:" << toHex(info.MapSize) << endl;
		*fout << "# Protection:" << toHex(info.Protection) << endl;
		*fout << "# Shared:" << toHex(info.Shared) << endl;
		*fout << "# Type:" << toHex(info.Type) << endl;

		rc = OS_ProtectMemory(pid, 
			(VOID*)sec->saddr, 
			sec->eaddr - sec->saddr, 
			OS_PAGE_PROTECTION_TYPE_READ | OS_PAGE_PROTECTION_TYPE_WRITE);
		*fout << "# OS Return Code of ProtectMemory " << rc.generic_err << endl;;
	}
}


// IAT fixing
void FixIAT()
{	
#if LOG_DUMP == 1
	*fout << "# IAT Fixing" << endl;
#endif // LOG_DUMP == 1

	ADDRINT addr, fnaddr;
	for (auto &imp : imp_list) {
		
		addr = imp.addr;
		fnaddr = imp.func_addr;
		if (fnaddr == 0) {
			for (auto obf_call : obf_calls) {
				if (obf_call.indaddr == 0) continue;
				if (addr == obf_call.indaddr) {
					fnaddr = obf_call.dst;
					imp.func_addr = fnaddr;
					auto fn = GetFunctionInfo(fnaddr);
					auto n = ResolveForwardedFunc(fn->module_name, fn->name);
					fn->module_name = n.dll;
					fn->name = n.fn;
					imp.dll_name = fn->module_name;
					imp.func_name = fn->name;
					break;
				}
			}		
		}		      
		unsigned char* pc = reinterpret_cast<unsigned char*>(addr);
		PIN_SafeCopy(pc, &fnaddr, ADDRSIZE);
#if LOG_DUMP == 1
		*fout << "# " << imp << endl;
#endif
	}
}

// call/goto fixing
void FixCall()
{
#if LOG_DUMP == 1
	*fout << "# Call Fixing" << endl;
#endif // LOG_DUMP == 1

	UINT8 byts[16];
	size_t sz;
	unsigned char* pc;
	EXCEPTION_INFO pExinfo;

	for (auto obf_call: obf_calls)
	{	
		// skip obf_call from IAT
		if (obf_call.src == 0) continue;

		ADDRINT fn_addr = obf_call.dst;			
		for (auto imp : imp_list) {
			if (imp.func_addr == obf_call.dst) {
				*fout << toHex(obf_call.src) << '\t' << obf_call.get_mnem() << '\t' << imp.dll_name << '\t' << imp.func_name << endl;
				obf_call.indaddr = imp.addr;
				pc = reinterpret_cast<unsigned char*>(obf_call.src);				
				sz = obf_call.to_bytes(byts);
				size_t num_copied = PIN_SafeCopyEx(pc, byts, sz, &pExinfo);
#if LOG_DUMP == 1
				*fout << "# " << obf_call << endl;
				*fout << "# Patched: " << num_copied << endl;
#endif // LOG_DUMP == 1
				break;
			}
		}					
	}
}


////////////////////////////////////////////


// ----------------------------------------------------------------------------------------------------------
// Forwarding 된 api 함수 복원
// 
//  ucrt --> ms-win-crt-*
//	kernelbase --> ms-win-crt-*, kernel32
//	ntdll --> kernel32
//	gdi32full --> gdi32  : dll 이름만 바꿈(?)
//  * 계속 보완 해야 됨
//------------------------------------------------------------------------------------------------------------
void ResolveForwardedFunc(vector<IAT_INFO>& imp_list)
{
	
	for (auto &e : imp_list) {

		e.addr -= main_img_saddr;
		ResolveForwardedFunc(e.dll_name, e.func_name);
	}
	// remove themida iat(?)
	std::vector<IAT_INFO>::iterator it;
	for (it = imp_list.begin(); it != imp_list.end(); it++) {
		if (it->func_addr == (ADDRINT)(-1)) {
			break;
		}
	}
	imp_list.erase(it, imp_list.end());
}

FN_INFO ResolveForwardedFunc(string mod_name, string fn_name)
{
	if (mod_name.find("gdi32full.") != string::npos) {
		// 일단 무조건...
		mod_name = string("GDI32.DLL");
	}
	else if (mod_name.find("ucrtbase.") != string::npos) {
		const char* crt_dll_name = get_crt_dll_name(fn_name.c_str());
		if (crt_dll_name) {
			mod_name = string(crt_dll_name);
		}
	}
	else if (mod_name.find("kernelbase.") != string::npos) {

		const char* crt_dll_name = get_crt_dll_name(fn_name.c_str());
		if (crt_dll_name) {
			mod_name = string(crt_dll_name);
		}
		else {

			std::set<std::string>::iterator it = kernel32_funcs.find(fn_name);
			if (it != kernel32_funcs.end()) {
				mod_name = string("kernel32.dll");
			}
			else {
				// KERNELBASE 로 그냥 두자..
			}
		}
	}
	else if (mod_name.find("ntdll.") != string::npos) {

		// 전, 후 함수 확인해야되는데 ... 일단 무조건 바꾸는 걸로
		const char* kname = get_ntdll_to_kernel32_name(fn_name.c_str());

		if (kname) {
			mod_name = string("kernel32.dll");
			fn_name = string(kname);
		}
	}
	return { mod_name, fn_name };
}




void MakeDllList() {
	IAT_DLL_INFO dll_info;	
	
#if LOG_DUMP == 1
	*fout << "# Making DLL List" << endl;
#endif

	bool is_first_fn = true;
	for (auto &e : imp_list) {
#if LOG_DUMP == 1
		
		*fout << "# " << toHex(e.addr) << ' ' << toHex(e.func_addr) << ' ' << e.func_name << ' ' << e.dll_name << endl;
#endif
		if (e.func_addr == 0) {
			// if zero address is repeated, 
			// we may have missed some api functions. 
			// The last few entries of IAT is fixed because the text section refers to those locations. 
			// Then we skip zeros before the last entries. 
			// TODO: fixed locations are in the middle of IAT...
			// 
			if (is_first_fn) continue;	
			dll_list.push_back(dll_info);	// vector push_back copies an object when the object is pushed.
			is_first_fn = true;
			continue;
		}		
		if (is_first_fn) {
			dll_info.first_func = e.addr - main_img_saddr;	// RVA
			dll_info.nfunc = 1;
			dll_info.name = e.dll_name;
			is_first_fn = false;
			continue;
		}			
		dll_info.nfunc++;
	}

#if LOG_DUMP == 1
	*fout << "# DLL List" << endl;
	for (auto e : dll_list) {
		*fout << "# " << e.name << ' ' << toHex(e.first_func) << ' ' << e.nfunc << endl;
	}
	*fout << endl;
#endif
	
}


// Make Import Section

void GetImportComponentSize(UINT32* iidsize0, UINT32* iltsize0, UINT32* iinsize0)
{
	UINT32 iidsize = 0;	// _IMAGE_IMPORT_DESCRIPTOR size
	UINT32 iltsize = 0;	// IAT Size
	UINT32 iinsize = 0;	// _IMAGE_IMPORT_BY_NAME size

	size_t n_dll = dll_list.size();
	size_t n_fn = imp_list.size();
	iidsize = (n_dll + 1) * 20;
	iltsize = n_fn * ADDRSIZE;

	// iin dll name size
	for (auto e: dll_list) {
		int len = e.name.size() + 1;	// consider null termination			
		iinsize += Align(len, 2);
	}

	// iin func name size
	for (auto e: imp_list) {
		// ordinal functions do not have a name
		if (e.func_name.find("Ordinal_") == string::npos) {
			int len = e.func_name.size() + 1;
			iinsize += 2;
			iinsize += Align(len, 2);
		}
	}

	*iidsize0 = iidsize;
	*iltsize0 = iltsize;
	*iinsize0 = iinsize;
}

void* MakeImportSection(UINT32* size, UINT32 *idt_size, UINT32 vloc)
{
#if LOG_DUMP == 1
	*fout << "Making Import Section" << endl;
#endif // LOG_DUMP == 1
	UINT32 iidsize;	// _IMAGE_IMPORT_DESCRIPTOR size
	UINT32 iltsize;	// IAT Size
	UINT32 iinsize;	// _IMAGE_IMPORT_BY_NAME size

	MakeDllList();
	GetImportComponentSize(&iidsize, &iltsize, &iinsize);

	UINT32 import_sec_size = Align((iidsize + iltsize + iinsize), 512);
	ADDRINT import_sec_buf = (ADDRINT)malloc(import_sec_size);
	int ndll = dll_list.size();
	
	// Make Import Directory Table
	NW::IMAGE_IMPORT_DESCRIPTOR* iid = (NW::IMAGE_IMPORT_DESCRIPTOR*)(import_sec_buf);

	ADDRINT ilt0 = import_sec_buf + iidsize;
	ADDRINT ilt = ilt0;

	int i = 0;

	for (auto &e: dll_list) {
		*fout << "DLL " << e.name << ' ' << e.nfunc << ' ' << toHex(vloc + (ADDRINT)(&iid[i]) - import_sec_buf) << endl;
		iid[i].OriginalFirstThunk = ilt - import_sec_buf + vloc;
		iid[i].ForwarderChain = 0;
		iid[i].TimeDateStamp = 0;		
		iid[i].FirstThunk = e.first_func;  
		ilt += ADDRSIZE * (e.nfunc + 1); 
		i++;
	}
	memset(&iid[i], 0, sizeof(NW::IMAGE_IMPORT_DESCRIPTOR));  // last import directory entry

	// Make Import Names & IAT
	ADDRINT iin = ilt0 + iltsize;
	
	iid = (NW::IMAGE_IMPORT_DESCRIPTOR*)(import_sec_buf); // import names
	ilt = ilt0;	// IAT
	
	i = 0;
	string prev_dll_name;
	for (auto &e: imp_list) {
		ADDRINT iat_addr = e.addr;
		ADDRINT func_addr = e.func_addr;
		string dll_name = e.dll_name;
		string func_name = e.func_name;
		
		*fout << e << endl;
		// zero bytes between DLLs which means all function names are written and dll name should be written
		// if zero bytes are repeated, there are some missed functions				
		if (func_addr == 0) {						
			// Write DLL Names in Image Import Names Table		
			*fout << "DLL Name: " << prev_dll_name << ' ' << i << endl;
			if (prev_dll_name.length() > 0) {
				put_xword(ilt, 0);
				ilt += ADDRSIZE;

#if LOG_DUMP == 1			
				* fout << "# IIN " << toHex(iin - import_sec_buf + vloc) << ' ' << prev_dll_name << endl;
#endif // LOG_DUMP == 1		

				int len = prev_dll_name.length() + 1;
				put_many_bytes(iin, (ADDRINT)prev_dll_name.c_str(), len);
				iid[i].Name = iin - import_sec_buf + vloc;
				iin = iin + Align(len, 2);
				i++;
			}
		}

		// ordinal function		
		else if (func_name.find("Ordinal_") != string::npos) {
			ADDRINT ilt_val;
			char* stopstr;
			string temp = func_name.substr(8);
			ilt_val = (ADDRINT)std::strtoul(temp.c_str(), &stopstr, 10);
			ilt_val |= IMAGE_ORDINAL_FLAG;

			put_xword(ilt, ilt_val);
			PIN_SafeCopy((void*)iat_addr, (const void*)& ilt_val, ADDRSIZE);
			ilt += ADDRSIZE;

		}

		// name function
		else {
			ADDRINT ilt_val = iin - import_sec_buf + vloc;
			put_xword(ilt, ilt_val);
#if LOG_DUMP == 1
			*fout << "# ILT " << toHex(ilt) << " ILT_VAL:" << toHex(ilt_val) << endl;
#endif
			PIN_SafeCopy((void*)(iat_addr + main_img_saddr), (const void*)& ilt_val, ADDRSIZE);
			ilt += ADDRSIZE;			

			put_word(iin, 0);
			iin += 2;
#if LOG_DUMP == 1			
			*fout << "# IIN " << toHex(iin - import_sec_buf + vloc) << ' ' << func_name << endl;
#endif // LOG_DUMP == 1						
			int len1 = func_name.length() + 1;
			put_many_bytes(iin, (ADDRINT)func_name.c_str(), len1);						
			iin += Align(len1, 2);
		}

		prev_dll_name = dll_name;
	}

	*size = import_sec_size;
	*idt_size = iidsize;
	return (void*)import_sec_buf;
}

void* MakeImportSectionInRdata(UINT32* size, UINT32* idt_size, UINT32* vloc, UINT32 last_addr)
{

#if LOG_DUMP == 1
	* fout << "Making Import Section" << endl;
#endif // LOG_DUMP == 1
	UINT32 iidsize;	// _IMAGE_IMPORT_DESCRIPTOR size
	UINT32 iltsize;	// IAT Size
	UINT32 iinsize;	// _IMAGE_IMPORT_BY_NAME size

	MakeDllList();
	GetImportComponentSize(&iidsize, &iltsize, &iinsize);
	*idt_size = iidsize;

	UINT32 import_sec_size = Align((iidsize + iltsize + iinsize), 512);
	*size = import_sec_size;
	
	*vloc = last_addr - import_sec_size;
	ADDRINT import_sec_buf = *vloc + main_img_saddr;

#if LOG_DUMP == 1			
	* fout << "IID Location:" << toHex(import_sec_buf) << endl;
#endif

	int ndll = dll_list.size();

	// Make Import Directory Table
	NW::IMAGE_IMPORT_DESCRIPTOR* iid = (NW::IMAGE_IMPORT_DESCRIPTOR*)(import_sec_buf);

	ADDRINT ilt0 = import_sec_buf + iidsize;
	ADDRINT ilt = ilt0;

	int i = 0;

	for (auto& e : dll_list) {
		*fout << "DLL " << e.name << ' ' << e.nfunc << ' ' << toHex(*vloc + (ADDRINT)(&iid[i]) - import_sec_buf) << endl;
		iid[i].OriginalFirstThunk = ilt - import_sec_buf + *vloc;
		iid[i].ForwarderChain = 0;
		iid[i].TimeDateStamp = 0;
		iid[i].FirstThunk = e.first_func;
		ilt += ADDRSIZE * (e.nfunc + 1);
		i++;
	}
	memset(&iid[i], 0, sizeof(NW::IMAGE_IMPORT_DESCRIPTOR));  // last import directory entry

	// Make Import Names & IAT
	ADDRINT iin = ilt0 + iltsize;

	iid = (NW::IMAGE_IMPORT_DESCRIPTOR*)(import_sec_buf); // import names
	ilt = ilt0;	// IAT

	i = 0;
	string prev_dll_name;
	for (auto& e : imp_list) {
		ADDRINT iat_addr = e.addr;
		ADDRINT func_addr = e.func_addr;
		string dll_name = e.dll_name;
		string func_name = e.func_name;

		*fout << e << endl;
		// zero bytes between DLLs which means all function names are written and dll name should be written
		// if zero bytes are repeated, there are some missed functions				
		if (func_addr == 0) {
			// Write DLL Names in Image Import Names Table		
			*fout << "DLL Name: " << prev_dll_name << ' ' << i << endl;
			if (prev_dll_name.length() > 0) {
				put_xword(ilt, 0);
				ilt += ADDRSIZE;

#if LOG_DUMP == 1			
				* fout << "# IIN " << toHex(iin - import_sec_buf + *vloc) << ' ' << prev_dll_name << endl;
#endif // LOG_DUMP == 1		

				int len = prev_dll_name.length() + 1;
				put_many_bytes(iin, (ADDRINT)prev_dll_name.c_str(), len);
				iid[i].Name = iin - import_sec_buf + *vloc;
				iin = iin + Align(len, 2);
				i++;
			}
		}

		// ordinal function		
		else if (func_name.find("Ordinal_") != string::npos) {
			ADDRINT ilt_val;
			char* stopstr;
			string temp = func_name.substr(8);
			ilt_val = (ADDRINT)std::strtoul(temp.c_str(), &stopstr, 10);
			ilt_val |= IMAGE_ORDINAL_FLAG;

			put_xword(ilt, ilt_val);
			PIN_SafeCopy((void*)iat_addr, (const void*)&ilt_val, ADDRSIZE);
			ilt += ADDRSIZE;

		}

		// name function
		else {
			ADDRINT ilt_val = iin - import_sec_buf + *vloc;
			put_xword(ilt, ilt_val);
#if LOG_DUMP == 1
			* fout << "# ILT " << toHex(ilt) << " ILT_VAL:" << toHex(ilt_val) << endl;
#endif
			PIN_SafeCopy((void*)(iat_addr + main_img_saddr), (const void*)&ilt_val, ADDRSIZE);
			ilt += ADDRSIZE;

			put_word(iin, 0);
			iin += 2;
#if LOG_DUMP == 1			
			* fout << "# IIN " << toHex(iin - import_sec_buf + *vloc) << ' ' << func_name << endl;
#endif // LOG_DUMP == 1						
			int len1 = func_name.length() + 1;
			put_many_bytes(iin, (ADDRINT)func_name.c_str(), len1);
			iin += Align(len1, 2);
		}

		prev_dll_name = dll_name;
	}

	return (void*)import_sec_buf;
}


void DumpData(const char* fname, ADDRINT start, UINT32 size)
{
	ofstream file1(fname, ios::out | ios::binary);
	file1.write((const char*)start, size);
	file1.close();
}

typedef void* (__stdcall* f_CheckSumMappedFile)(void*, NW::DWORD, NW::DWORD*, NW::DWORD*);
#undef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE (NW::HANDLE)(-1)

ADDRINT Align(ADDRINT dwValue, ADDRINT dwAlign)
{
	if (dwAlign) {
		if (dwValue % dwAlign) {
			return (dwValue + dwAlign) - (dwValue % dwAlign);
		}
	}
	return dwValue;
}

void put_qword(ADDRINT addr, UINT64 val)
{
	UINT64* p = (UINT64*)addr;
	*p = val;
}
void put_dword(ADDRINT addr, UINT32 val)
{
	UINT32* p = (UINT32*)addr;
	*p = val;
}
void put_word(ADDRINT addr, UINT16 val)
{
	UINT16* p = (UINT16*)addr;
	*p = val;

}

void put_xword(ADDRINT addr, ADDRINT val) {
	ADDRINT* p = (ADDRINT*)addr;
	*p = val;
}

void put_many_bytes(ADDRINT dst, ADDRINT src, int len)
{
	UINT8* psrc = (UINT8*)src;
	UINT8* pdst = (UINT8*)dst;
	for (int i = 0; i < len; i++) {
		*pdst++ = *psrc++;
	}
}

UINT64 get_qword(ADDRINT addr, ADDRINT* paddr)
{
	UINT64* p = (UINT64*)addr;
	if (paddr)* paddr += 8;
	return *p;
}
UINT32 get_dword(ADDRINT addr, ADDRINT* paddr)
{
	UINT32* p = (UINT32*)addr;
	if (paddr)* paddr += 4;
	return *p;

}
UINT16 get_word(ADDRINT addr, ADDRINT* paddr)
{
	UINT16* p = (UINT16*)addr;
	if (paddr)* paddr += 2;

	return *p;;

}
void get_many_bytes(ADDRINT dst, ADDRINT src, int len)
{
	UINT8* psrc = (UINT8*)src;
	UINT8* pdst = (UINT8*)dst;
	for (int i = 0; i < len; i++) {
		*pdst++ = *psrc++;
	}
}

// dump image as hex text
void DumpHex()
{
	// dump as text file
	mod_info_t* modinfo = GetModuleInfo(main_img_saddr);
	if (modinfo == NULL) return;

	size_t max_blk_size = 0;
	for (auto it = modinfo->sec_infos.begin(); it != modinfo->sec_infos.end(); it++)
	{
		sec_info_t* secinfo = *it;
		max_blk_size = max(max_blk_size, secinfo->eaddr - secinfo->saddr);
	}

	UINT8* mem_buf = (UINT8*)malloc(max_blk_size);

	for (auto it = modinfo->sec_infos.begin(); it != modinfo->sec_infos.end(); it++)
	{
		sec_info_t* secinfo = *it;
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

void KeepHeader()
{
	hdr_at_load = malloc(4096);
	memcpy(hdr_at_load, (const void*)main_img_saddr, 4096);
}


// utility for calculating overlay offset

ADDRINT GetNextOffset(OFFSET_AND_SIZE o_s) 
{
	return o_s.offset + o_s.size;
}


OFFSET_AND_SIZE GetLargerWithinFile(
	OFFSET_AND_SIZE maxOffsetAndSize,
	OFFSET_AND_SIZE offsetAndSize)
{
	ADDRINT nextAddr = GetNextOffset(offsetAndSize);
	ADDRINT maxNextAddr = GetNextOffset(maxOffsetAndSize);
	if (nextAddr <= file_size && nextAddr > maxNextAddr) {
		return offsetAndSize;
	}
	return maxOffsetAndSize;
}

OFFSET_AND_SIZE GetOverlayDataStartOffsetAndSize(void* hdr)
{		
	ADDRINT loadBase0 = (ADDRINT)hdr;
	NW::IMAGE_DOS_HEADER* dos0 = (NW::IMAGE_DOS_HEADER*)loadBase0;
	NW::IMAGE_NT_HEADERS* nt0 = (NW::IMAGE_NT_HEADERS*)(loadBase0 + dos0->e_lfanew);
	NW::IMAGE_SECTION_HEADER* sect0 = (NW::IMAGE_SECTION_HEADER*)
		(loadBase0 +
			dos0->e_lfanew +
			sizeof(NW::DWORD) +
			sizeof(nt0->FileHeader) +
			nt0->FileHeader.SizeOfOptionalHeader);

	OFFSET_AND_SIZE maxOffsetAndSize = { 0, 0 }; 
	
	// optional header
	OFFSET_AND_SIZE ophdr_o_s = { 
		(ADDRINT) & (nt0->OptionalHeader) - loadBase0, 
		nt0->FileHeader.SizeOfOptionalHeader };
	maxOffsetAndSize = GetLargerWithinFile(maxOffsetAndSize, ophdr_o_s);

	// sections
	int nsec = nt0->FileHeader.NumberOfSections;

	for (auto i = 0; i < nsec; i++) {
		OFFSET_AND_SIZE sect_o_s = { sect0[i].PointerToRawData, sect0[i].SizeOfRawData };
		maxOffsetAndSize = GetLargerWithinFile(maxOffsetAndSize, sect_o_s);
	}

	// data directories

	for (auto e : nt0->OptionalHeader.DataDirectory) {
		// entry
		OFFSET_AND_SIZE de = { e.VirtualAddress, e.Size };
		maxOffsetAndSize = GetLargerWithinFile(maxOffsetAndSize, de);
	}

	if (file_size > GetNextOffset(maxOffsetAndSize)) {
		ADDRINT next_addr = GetNextOffset(maxOffsetAndSize);
		size_t sz = file_size - next_addr;
		return {next_addr, sz};
	}
	return { 0, 0 };
}


// dump memory of each section
void DumpUnpackedFile()
{	
	LOG("DUMP file");
	ADDRINT img_base = main_img_saddr;

	// use original header from loaded pe
	// because themida break the headers from memory dump
	void* hdr = hdr_at_load;
	ADDRINT loadBase0 = (ADDRINT)hdr;

	NW::IMAGE_DOS_HEADER* dos0 = (NW::IMAGE_DOS_HEADER*)loadBase0;
	NW::IMAGE_NT_HEADERS* nt0 = (NW::IMAGE_NT_HEADERS*)(loadBase0 + dos0->e_lfanew);
	NW::IMAGE_SECTION_HEADER* sect0 = (NW::IMAGE_SECTION_HEADER*)
		(loadBase0 + 
			dos0->e_lfanew + 
			sizeof(NW::DWORD) + 
			sizeof(nt0->FileHeader) + 
			nt0->FileHeader.SizeOfOptionalHeader);
	if (dos0->e_magic != 0x5A4D || nt0->Signature != 0x4550) {
		LOG("[Err] LoadExeFile: Invalid signatures");
		return;
	}

	// Check Overlay
	OFFSET_AND_SIZE overlay_os = GetOverlayDataStartOffsetAndSize(hdr);
	if (overlay_os.offset != 0) {
		*fout << "Overlay Data Detected. Offset:" << toHex(overlay_os.offset) << " Size:" << toHex(overlay_os.size) << endl;
		DumpUnpackedFile_Overlay();
		return;
	}

	// set OEP
	nt0->OptionalHeader.AddressOfEntryPoint = oep;

	// add one more section for import
	
	int nsec = nt0->FileHeader.NumberOfSections;
	nt0->FileHeader.NumberOfSections++;

	// Original Section that themida included in the packed binary
	UINT32 floc = 0x1000;
	for (int i = 0; i < nsec; i++) {
		UINT32 vsize = sect0[i].Misc.VirtualSize;
		UINT32 fsize_a = Align(vsize, nt0->OptionalHeader.FileAlignment);
		sect0[i].SizeOfRawData = fsize_a;
		sect0[i].PointerToRawData = floc;
		floc = floc + fsize_a;
	}

	nt0->OptionalHeader.ImageBase = img_base;

	// because themida deleted relocation
	nt0->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

	// start of appended section
	UINT32 vloc = sect0[nsec - 1].VirtualAddress +
		Align(sect0[nsec - 1].Misc.VirtualSize, nt0->OptionalHeader.SectionAlignment);

	// import section	
	UINT32 vloc_imp = vloc;
	UINT32 idt_size;
	UINT32 vsize_imp;

	void* fdata_imp = MakeImportSection(&vsize_imp, &idt_size, vloc_imp);
	if (!fdata_imp) {
		return;
	}

	vsize_imp = Align(vsize_imp, nt0->OptionalHeader.SectionAlignment);
	UINT32 fsize_imp = Align(vsize_imp, nt0->OptionalHeader.FileAlignment);

	sect0[nsec].VirtualAddress = vloc_imp;
	sect0[nsec].Misc.VirtualSize = vsize_imp;
	sect0[nsec].SizeOfRawData = fsize_imp;
	sect0[nsec].PointerToRawData = floc;
	sect0[nsec].Characteristics = sect0[1].Characteristics;
	void* pp = &sect0[nsec].Name;
	strcpy((char*)pp, ".import");

	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = vloc_imp;
	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = idt_size;
	
	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = (UINT32)(imp_list.begin()->addr - main_img_saddr);
	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = (UINT32)(imp_list.rbegin()->addr - imp_list.begin()->addr + ADDRSIZE);


	// ----------------------------------------------------------------------------------------------------
	floc = floc + fsize_imp;
	vloc = vloc_imp + Align(vsize_imp, nt0->OptionalHeader.SectionAlignment);
	
	nt0->OptionalHeader.SizeOfImage = vloc;
	nt0->OptionalHeader.SizeOfHeaders = 0x400;

	string ext;
	if (isDLLAnalysis) ext = "_dmp.dll";
	else ext = "_dmp.exe";
	string outfile;
	outfile = main_file_name; 
	FILE* fp = NULL;
	int cnt = 0;	
	while (fp == NULL) {
		outfile = main_file_name;
		if (cnt > 0) {
			outfile += "_" + toHex(cnt);
		}
		outfile += ext;
		fp = fopen(outfile.c_str(), "wb");
		cnt++;
	}
	UINT32 off = 0;;
	fwrite((const void*)hdr, 4096, 1, fp);

	off += 4096;

	for (int i = 0; i < nsec; i++) {
		UINT32 fsize = sect0[i].SizeOfRawData;
		ADDRINT addr = sect0[i].VirtualAddress + img_base;
		fwrite((const void*)addr, fsize, 1, fp);
		off += fsize;
	}

	fwrite((const void*)fdata_imp, fsize_imp, 1, fp);
	off += fsize_imp;

	free(hdr);
	free(fdata_imp);

	fclose(fp);	
}

/// =====================
// dump memory of each section and import section at 
void DumpUnpackedFile_Overlay()
{
	ADDRINT img_base = main_img_saddr;

	// use original header from loaded pe
	// because themida break the headers from memory dump
	void* hdr = hdr_at_load;
	ADDRINT loadBase0 = (ADDRINT)hdr;

	NW::IMAGE_DOS_HEADER* dos0 = (NW::IMAGE_DOS_HEADER*)loadBase0;
	NW::IMAGE_NT_HEADERS* nt0 = (NW::IMAGE_NT_HEADERS*)(loadBase0 + dos0->e_lfanew);
	NW::IMAGE_SECTION_HEADER* sect0 = (NW::IMAGE_SECTION_HEADER*)
		(loadBase0 +
			dos0->e_lfanew +
			sizeof(NW::DWORD) +
			sizeof(nt0->FileHeader) +
			nt0->FileHeader.SizeOfOptionalHeader);

	// set OEP
	nt0->OptionalHeader.AddressOfEntryPoint = oep;

	// add one more section for import

	int nsec = nt0->FileHeader.NumberOfSections;
	nt0->FileHeader.NumberOfSections++;

	// Original Section that themida included in the packed binary
	UINT32 floc = 0x1000;
	for (int i = 0; i < nsec; i++) {
		UINT32 vsize = sect0[i].Misc.VirtualSize;
		UINT32 fsize_a = Align(vsize, nt0->OptionalHeader.FileAlignment);
		sect0[i].SizeOfRawData = fsize_a;
		sect0[i].PointerToRawData = floc;
		floc = floc + fsize_a;
	}

	nt0->OptionalHeader.ImageBase = img_base;

	// because themida deleted relocation
	nt0->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

	
	// import section	
	UINT32 vloc_imp;
	UINT32 idt_size;
	UINT32 vsize_imp;

	void* fdata_imp = MakeImportSectionInRdata(&vsize_imp, &idt_size, &vloc_imp, sect0[1].VirtualAddress + sect0[1].SizeOfRawData);
	if (!fdata_imp) {
		return;
	}

	vsize_imp = Align(vsize_imp, nt0->OptionalHeader.SectionAlignment);
	UINT32 fsize_imp = Align(vsize_imp, nt0->OptionalHeader.FileAlignment);

	// IDT, INT, Names
	UINT32 vloc = sect0[2].VirtualAddress - vsize_imp;


	//sect0[nsec].VirtualAddress = vloc_imp;
	//sect0[nsec].Misc.VirtualSize = vsize_imp;
	//sect0[nsec].SizeOfRawData = fsize_imp;
	//sect0[nsec].PointerToRawData = floc;
	//sect0[nsec].Characteristics = sect0[1].Characteristics;
	//void* pp = &sect0[nsec].Name;
	//strcpy((char*)pp, ".import");

	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = vloc_imp;
	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = idt_size;

	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = (UINT32)(imp_list.begin()->addr - main_img_saddr);
	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = (UINT32)(imp_list.rbegin()->addr - imp_list.begin()->addr + ADDRSIZE);


	// ----------------------------------------------------------------------------------------------------
	floc = floc + fsize_imp;
	vloc = vloc_imp + Align(vsize_imp, nt0->OptionalHeader.SectionAlignment);

	nt0->OptionalHeader.SizeOfImage = vloc;
	nt0->OptionalHeader.SizeOfHeaders = 0x400;

	string ext;
	if (isDLLAnalysis) ext = "_dmp.dll";
	else ext = "_dmp.exe";
	string outfile;
	outfile = main_file_name;

	// read overlay data
	FILE* fp = NULL;
	fp = fopen(main_file_name.c_str(), "rb");
	
	OFFSET_AND_SIZE overlay_os = GetOverlayDataStartOffsetAndSize(hdr);
	void* overlay_data = malloc(overlay_os.size);
	fseek(fp, overlay_os.offset, SEEK_SET);
	fread(overlay_data, overlay_os.size, 1, fp);
	fclose(fp);
	fp = NULL;

	int cnt = 0;
	while (fp == NULL) {
		outfile = main_file_name;
		if (cnt > 0) {
			outfile += "_" + toHex(cnt);
		}
		outfile += ext;
		fp = fopen(outfile.c_str(), "wb");
		cnt++;
	}
	UINT32 off = 0;;
	fwrite((const void*)hdr, 4096, 1, fp);

	off += 4096;

	for (int i = 0; i < nsec; i++) {
		UINT32 fsize = sect0[i].SizeOfRawData;
		ADDRINT addr = sect0[i].VirtualAddress + img_base;
		fwrite((const void*)addr, fsize, 1, fp);
		off += fsize;
	}

	fwrite(overlay_data, overlay_os.size, 1, fp);
	fclose(fp);
	free(hdr);
}

/// =====================


/// <summary> Instrument instructions. </summary>
void INS_inst(INS ins, void *v)
{
	ADDRINT addr = INS_Address(ins);
	if (isDLLAnalysis)
	{
		if (addr == obf_dll_entry_addr) {
			dll_is_unpack_started = true;
			LOG("Unpack Started.\n");
		}
		if (!dll_is_unpack_started) return;
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
		set_meblock(addr);
		if (IS_TEXT_SEC(addr))
		{
			if (get_mwblock(addr) && get_meblock(addr) > 0)
			{				
				oep = addr - main_img_saddr;
				*fout << "OEP:" << toHex(oep) << endl;
				PIN_SaveContext(ctxt, &ctx0);
				PIN_SemaphoreSet(&sem_oep_found);
				PIN_SemaphoreWait(&sem_dump_finished);
			}
			return;
		}
	}
}


// EXE INS memory write analysis function 
void INS_MW_analysis(ADDRINT addr, size_t mSize, ADDRINT targetAddr)
{
	set_mwblock(targetAddr);


	if (current_obf_fn == NULL) return;
	if (isDLLAnalysis && IS_MAIN_IMG(targetAddr)) return;

	if (IS_MAIN_IMG(targetAddr)) return;
	if (targetAddr == 0) {
		current_obf_fn = 0;
		return;
	}
	if (GetModuleInfo(targetAddr) != NULL) return;

	for (size_t i = 0; i < mSize; i++)
	{
		obfaddr2fn[targetAddr + i] = current_obf_fn;
	}

#if DEBUG == 1
	* fout << "# W: " << toHex(addr) << ' ' << toHex(targetAddr) << ' ' << mSize << endl;
#endif
}

// EXE INS memory read analysis function 
void INS_MR_analysis(ADDRINT targetAddr)
{
	fn_info_t *finfo = GetFunctionInfo(targetAddr);
	if (finfo == NULL) return;
	current_obf_fn = finfo;
#if DEBUG == 1
	*fout << "# API Read: " << toHex(targetAddr) << ' ' << *current_obf_fn << endl;
#endif
}


// ========================================================================================================================
// Common Callbacks
// ========================================================================================================================

// IMG instrumentation function for EXE files
void IMG_Instrument(IMG img, void *v)
{
	// Trim image name
	string imgname = IMG_Name(img);
	size_t pos = imgname.rfind("\\") + 1;
	imgname = imgname.substr(pos);
	TO_LOWER(imgname);
	mod_info_t *modinfo = NULL;
	if (module_info_m.find(imgname) != module_info_m.end()) return;
	
	bool kernel32 = false;
	TO_LOWER(imgname);
	if (imgname.find("kernel32.") != string::npos) kernel32 = true;

	// Record symbol information of a loaded image 
	ADDRINT saddr = IMG_LowAddress(img);
	ADDRINT eaddr = IMG_HighAddress(img);
	modinfo = new mod_info_t(imgname, saddr, eaddr);
	module_info_m[imgname] = modinfo;	

	bool is_main = false;

	if (isDLLAnalysis)
	{
		// obfuscated dll module is loaded
		if (imgname == obf_dll_name)
		{
			is_main = true;
			main_file_name = imgname;
			obf_dll_entry_addr = IMG_EntryAddress(img);
			main_img_saddr = saddr;
			main_img_eaddr = eaddr;	
			main_img_info = modinfo;

			SEC sec = IMG_SecHead(img);
			main_txt_saddr = SEC_Address(sec);
			main_txt_eaddr = main_txt_saddr + SEC_Size(sec);

			if (ir_file != "") AdjustLoadedAddress(main_img_saddr);

			KeepHeader();
			ifstream in(main_file_name.c_str(), ifstream::ate | ifstream::binary);
			file_size = in.tellg();
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
			is_main = true;
			main_file_name = imgname;
			main_img_saddr = saddr;
			main_img_eaddr = eaddr;
			main_img_info = modinfo;

			if (ir_file != "") AdjustLoadedAddress(main_img_saddr);

			// *fout << toHex(instrc_saddr) << ' ' << toHex(instrc_eaddr) << endl;
			SEC sec = IMG_SecHead(img);
			main_txt_saddr = SEC_Address(sec);
			main_txt_eaddr = main_txt_saddr + SEC_Size(sec);

			KeepHeader();
			ifstream in(main_file_name.c_str(), ifstream::ate | ifstream::binary);
			file_size = in.tellg();
		}
	}
	
	if (is_main) 
	{
		*fout << "IMG:" << *modinfo << endl;
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
		if (is_main) 
		{
			*fout << "SECTION:" << *secinfo << endl;
		}		
		
		if (SEC_Name(sec) == ".text" || cnt == 0)
		{
			// by default, the first section is considered as .text section
			// if the executable file is compiled in debug mode, the first section is .textbss and the second section is .text
			if (IS_MAIN_IMG(saddr)) {				
				main_txt_saddr = SEC_Address(sec);
				main_txt_eaddr = main_txt_saddr + SEC_Size(sec);
			}

			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
			{
				string rtnname = RTN_Name(rtn);

				if (rtnname == ".text") continue;

				ADDRINT saddr = RTN_Address(rtn);
				ADDRINT eaddr = saddr + RTN_Range(rtn);
				fn_info_t *fninfo = new fn_info_t(imgname, rtnname, saddr, eaddr);
				*fout << *fninfo << endl;
				fn_info_m[saddr] = fninfo;
				fn_str_2_fn_info[make_pair(imgname, rtnname)] = fninfo;
				module_info_m[imgname]->fn_infos.push_back(fninfo);

				if (kernel32) kernel32_funcs.insert(rtnname);

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
	FixMemoryProtection();
	// Fix Memory Protection for VMProtect 3.x and Themida 3.x
	if (packer_type == "vmp" && ADDRSIZE == 8 || packer_type == "tmd3") {
		LOG(msg_hdr + "Resetting Memory Protection\n");
		FixMemoryProtection();
	}

	if (imp_start_addr == 0) {
		// Search for IAT area.
		LOG(msg_hdr + "Searching for IAT Area.\n");
		bool isIAT = FindIAT();
		if (!isIAT)
		{
			LOG(msg_hdr + "Cannot find an IAT are candidate in the binary.\n");
		}
	}
	
	if (obf_call_candidates.empty()) {
		// Search for obfuscated API calls.
		LOG(msg_hdr + "Searching for obfuscated calls.\n");
		FindObfuscatedAPICalls();
#if LOG_CALL_CHECK == 1
		* fout << "# Obfuscated Calls:" << endl;
		*fout << "# ------------------------------" << endl;
		for (auto e : obf_calls) {
			*fout << "# " << e << endl;
		}
		*fout << endl;
#endif
	}
	
	if (packer_type == "vmp" || packer_type == "tmd2" && ADDRSIZE == 8 || packer_type == "tmd3") {
		// Resolve obfuscated API calls for vmp & Theamida x64 (2.x)
		LOG(msg_hdr + "Resolving obfuscated API Calls.\n");

#if LOG_CALL_CHECK == 1
		*fout << "# Obfuscated Call Candidates" << endl;
		for (auto e : obf_call_candidates) {
			*fout << e << endl;
		}
#endif
		isCheckAPIStart = true;
		PIN_SemaphoreWait(&sem_resolve_api_end);
	}	
	LOG(msg_hdr + "Resolving obfuscated API Calls finished.\n");
	
	if (packer_type == "vmp") {
		LOG(msg_hdr + "Resolve forwarded functions.\n");
		ReconstructImpList();
	}
	

	PrintIATArea();

	LOG(msg_hdr + "Fixing IAT.\n");
	FixIAT();
	
	PrintIATArea();


	LOG(msg_hdr + "Fixing obfuscated calls.\n");
	FixCall();	
	
	LOG(msg_hdr + "Fixing obfuscated calls finished.\n");

	LOG(msg_hdr + "Dumping PE file.\n");
	DumpUnpackedFile();	

	LOG(msg_hdr + "Semaphore set\n");
	PIN_SemaphoreSet(&sem_dump_finished);	

	LOG(msg_hdr + "Semaphore set2\n");
	((ofstream*)fout)->close();
	PIN_ExitProcess(-1);

	LOG(msg_hdr + "exit\n");


}

static int hadException = FALSE;

// exception handler
static void OnException(THREADID threadIndex,
	CONTEXT_CHANGE_REASON reason,
	const CONTEXT* ctxtFrom,
	CONTEXT* ctxtTo,
	INT32 info,
	VOID* v)
{
	if (reason == CONTEXT_CHANGE_REASON_EXCEPTION)
	{
		UINT32 exceptionCode = info;
		// Depending on the system and CRT version, C++ exceptions can be implemented 
		// as kernel- or user-mode- exceptions.
		// This callback does not not intercept user mode exceptions, so we do not 
		// log C++ exceptions to avoid difference in output files.
		if (exceptionCode == 0xc0000096 || exceptionCode == 0xc000001d || exceptionCode == 0xc0000005) {
			*fout << "# Exception code *= " << toHex(exceptionCode) << endl;
			return;
		}
		if ((exceptionCode >= 0xc0000000) && (exceptionCode <= 0xcfffffff))
		{
			*fout << "# Exception code = " << toHex(exceptionCode) << endl;
			if (current_obfuscated_call) {
				*fout << "SKIP:" << toHex(current_obfuscated_call->src) << endl;
				*fout << "NO:" << current_obf_fn_pos << endl;
				WriteIntermediateResult(ir_file);
			}
			else {
				*fout << "From:" << toHex(PIN_GetContextReg(ctxtFrom, REG_INST_PTR)) << endl;
				*fout << "From:" << toHex(PIN_GetContextReg(ctxtTo, REG_INST_PTR)) << endl;
			}
			LOG("Exception:" + hexstr(exceptionCode) + "\n");
			LOG("Continue-with " + ir_file);
			((ofstream*)fout)->close();
			PIN_ExitProcess(-1);
		}
	}
}


void ReadIntermediateResult(string filename)
{
	LOG("Reading Intermediate Result:" + filename + "\n");
	string line, data_ty;	
	obf_call_t obfcall;
	string call_ty;	

	ifstream fin(filename.c_str());
	string current_status = "";
	while (fin.good()) {
		getline(fin, line);
		stringstream ss(line);
		if (line.find("OEP") != string::npos) {
			ss >> data_ty >> hex >> oep;
			continue;
		}
		else if (line.find("IMP") != string::npos) {
			ss >> data_ty >> hex >> imp_start_addr >> imp_end_addr;
			imp_start_addr += main_img_saddr;
			imp_end_addr += main_img_saddr;
			continue;
		}
		else if (line.find("OBFUSCATED CALL CANDIDATES") != string::npos) {
			current_status = "OBFUSCATED_CALL_CANDIDATES";
			continue;
		}
		else if (line.find("NEXT_POS") != string::npos) {
			ss >> data_ty >> current_obf_fn_pos;
			continue;
		}
		else if (line.find("DEOBFUSCATED CALL") != string::npos) {
			current_status = "DEOBFUSCATED_CALL";
			continue;
		}

		if (current_status == "OBFUSCATED_CALL_CANDIDATES") {
			ss >> call_ty >> hex >> obfcall.src >> hex >> obfcall.dst >> obfcall.n_prev_pad_byts;
			obfcall.ins_type = fromString(call_ty);
			obf_call_candidates.push_back(obfcall);
		}
		else if (current_status == "DEOBFUSCATED_CALL") {
			ss >> call_ty >> hex >> obfcall.src >> hex >> obfcall.dst;
			obfcall.ins_type = fromString(call_ty);
			obf_calls.push_back(obfcall);
		}
	}

	// so far obfuscated calls are in RVA
	// we will fix this after loading the main image

	fin.close();
	WriteIntermediateResult("test.txt");
	skip_until_oep = true;
}


void AdjustLoadedAddress(ADDRINT delta) {
	*fout << "# Adjusting Loaded Addresses\n";

	for (auto &e : obf_call_candidates) {
		*fout << "# e.src " << toHex(e.src) << "->";
		e.src += delta;
		*fout << toHex(e.src) << endl;
	}
	for (auto &e : obf_calls) {		
		*fout << "# e.src " << toHex(e.src) << "->";
		e.src += delta;
		*fout << toHex(e.src) << endl;
	}
	WriteIntermediateResult("test1.txt");

}

void WriteIntermediateResult(string filename)
{	
	*fout << "Writing intermediate result to " << filename << endl;
	ofstream ir_out(filename.c_str());
	
	ir_out << "OEP " << toHex(oep) << endl;
	ir_out << "IMP " << toHex(imp_start_addr - main_img_saddr) << " " << toHex(imp_end_addr - main_img_saddr) << endl;
	ir_out << "OBFUSCATED CALL CANDIDATES" << endl;
	for (auto e : obf_call_candidates) {
		ir_out << '\t' << toString(e.ins_type) << ' ' << toHex(e.src - main_img_saddr) << ' ' << toHex(e.dst) << ' ' << e.n_prev_pad_byts << endl;		
	}
	ir_out << "NEXT_POS " << (current_obf_fn_pos + 1) << endl;
	ir_out << "DEOBFUSCATED CALLS" << endl;
	for (auto e : obf_calls) {
		ir_out << '\t' << toString(e.ins_type) << ' ' << toHex(e.src - main_img_saddr) << ' ' << toHex(e.dst) << endl;
	}
	ir_out << endl;
	ir_out.close();
}




/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char* argv[])
{
	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid 
	if (PIN_Init(argc, argv))
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

	ir_file = KnobIntermediateResultFile.Value();
	if (ir_file == "") {
		*fout << "# no intermediate result" << endl;
		ir_file = "kdtir_0.txt";
	}
	else {
		ReadIntermediateResult(ir_file);
		size_t pos0 = ir_file.find('_');
		size_t pos1 = ir_file.find('.');
		stringstream sin(ir_file.substr(pos0 + 1, pos1 - pos0 - 1));
		size_t idx;
		sin >> idx;
		stringstream sout;
		idx++;
		sout << ir_file.substr(0, pos0 + 1) << idx << ".txt";
		ir_file = sout.str();		
	}


	/////////////////////////////////////////////////////////////////////////////////////////////
	PIN_InitSymbols();

	// Register Analysis routines to be called when a thread begins/ends
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	// Image Instrumentation
	IMG_AddInstrumentFunction(IMG_Instrument, 0);

	// Register function to be called to instrument traces
	if (packer_type == "vmp" || packer_type == "tmd3" || packer_type == "tmd2" || packer_type == "enigma") {
		TRACE_AddInstrumentFunction(TRC_inst, 0);		
	}

	// exception handling
	PIN_AddContextChangeFunction(OnException, 0);

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
