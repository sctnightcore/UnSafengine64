#include "ThemidaPinAnalyzer.h"

using namespace std;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool", "o", "result.txt", "specify file name for the result");
KNOB<string> KnobDLLFile(KNOB_MODE_WRITEONCE, "pintool", "dll", "", "specify packed dll file");
KNOB<bool> KnobMemoryTrace(KNOB_MODE_WRITEONCE,  "pintool", "memtrace", "0", "specify whether to record memory trace or not");
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
// API Detection Functions for x64
// ========================================================================================================================

// Find obfuscated API Calls
void EXE64_FindAPICalls()
{
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
		// is patched by Themida64 into
		// CALL rel32; db 00 (E8 __ __ __ __ ; 00)
		if (buf[idx] == 0xE8 && (buf[idx + 5] == 0x00 || buf[idx + 5] == 0x90))
		{

			addr = obf_txt_saddr + idx;
			target_addr = addr + 5 + buf[idx+1] + (buf[idx+2] << 8) + (buf[idx+3] << 16) + (buf[idx+4] << 24);
			sec_info_t *current_section = GetSectionInfo(addr);
			sec_info_t *target_section = GetSectionInfo(target_addr);

			if (current_section == NULL || target_section == NULL) continue;

			// obfuscated call target is selected by 
			// - call targets into other section of the main executables
			if (current_section->module_name == target_section->module_name &&
				current_section->saddr != target_section->saddr) {
				obf_call_addrs.push_back(make_pair(addr, target_addr));
			}
		}
	}
	free(buf);

}

bool EXE64_CheckExportArea(int step)
{
	bool retVal = false;
	size_t txtsize = obf_txt_eaddr - obf_txt_saddr;;
	UINT8 *buf = (UINT8*)malloc(txtsize);
	// buf has executable memory image
	PIN_SafeCopy(buf, (VOID*)obf_txt_saddr, txtsize);

	// step 1: find zero block
	if (step == 1) {
		bool isZeroBlk = true;
		if (addrZeroBlk != 0) goto free_buf;
		addrZeroBlk = 0;

		for (size_t blk = 0; blk < txtsize; blk += 0x1000) {
			isZeroBlk = true;
			for (size_t i = 0; i < 0x1000; i++) {
				if (buf[blk + i] != 0) {
					isZeroBlk = false;
					break;
				}
			}
			if (isZeroBlk) {
				addrZeroBlk = obf_txt_saddr + blk;
				retVal = true;
				goto free_buf;
			}
		}
	}
	// step 2: check whether the zero block is filled
	else if (step == 2) {
		bool isZeroBlk = true;
		if (addrZeroBlk == 0) {
			retVal = false;
			goto free_buf;
		}
		for (size_t i = 0; i < 0x1000; i++) {
			if (buf[addrZeroBlk - obf_txt_saddr + i] != 0) {
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

// Check External Reference from main image address for x64
void EXE64_CheckExportFunctions()
{
	bool isIAT = EXE64_CheckExportArea(2);
	if (!isIAT) return;

	size_t blksize = obf_txt_eaddr - addrZeroBlk;;
	UINT8 *buf = (UINT8*)malloc(blksize);
	PIN_SafeCopy(buf, (VOID*)addrZeroBlk, blksize);

	map<string, fn_info_t*> sorted_api_map;
	for (auto it = obfaddr2fn.begin(); it != obfaddr2fn.end(); it++) {
		fn_info_t *fninfo = it->second;
		string key = fninfo->module_name + '.' + fninfo->name;
		sorted_api_map[key] = fninfo;
	}

	ADDRINT current_addr = addrZeroBlk;
	ADDRINT rel_addr = 0;
	size_t idx = 0;
	vector<pair<ADDRINT, fn_info_t*>> result_vec;
	for (auto it = sorted_api_map.begin(); it != sorted_api_map.end(); it++, idx++) {
		
		// skip if the address points to an API function
		while (true) {
			current_addr = addrZeroBlk + idx * 8;
			rel_addr = idx * 8;

			if (rel_addr > 0x1000) {
				*fout << "IAT Size too big." << endl;
				goto free_buf;
			}

			ADDRINT addrval = buf[rel_addr + 7];
			for (int j = 6; j >= 0; j--) addrval = ((addrval << 8) | buf[rel_addr + j]);

			if (GetModuleInfo(addrval) == NULL) break;
			idx++;
		}
		
		// assign resolved function address to candidate IAT area
		fn_info_t *fninfo = it->second;
		result_vec.push_back(make_pair(current_addr - obf_img_saddr, it->second));
	}

	// print IAT info
	*fout << "IAT START: " << toHex(addrZeroBlk - obf_img_saddr) << endl;
	*fout << "IAT SIZE: " << toHex(idx * sizeof(ADDRINT)) << endl;
	for (auto it = result_vec.begin(); it != result_vec.end(); it++) {
		*fout << toHex(it->first) << "\taddr\t" << it->second->module_name << '\t' << it->second->name << endl;
	}


free_buf:
	free(buf);

}

// API Detect executable trace analysis function
void EXE64_TRC_APIDetect_analysis(CONTEXT *ctxt, ADDRINT addr, THREADID threadid)
{
	if (threadid != 0) return;

	if (isCheckAPIRunning) {
		// if obfuscated API checking is started and 
		// if the trace is in another section
		// then here is the obfuscated instructions that resolve 'call API_function'
		// These obfuscated instructions end by 'RET' instruction 
		// that jumps into API function code

		UINT8 buf[8];		
		ADDRINT stkptr = PIN_GetContextReg(ctxt, REG_STACK_PTR);		
		PIN_SafeCopy(buf, (VOID*)stkptr, 8);

		if (addr > obf_txt_eaddr && addr < obf_img_eaddr) {
			// DO NOTHING
			return;
		}

		// *fout << "RSP:" << toHex(stkptr) << " [RSP]:" << toHex(toADDRINT(buf)) << " Call Addr:" << toHex(current_callnextaddr) << endl;

		// if the trace in in API function
		// then here is the API function. 
		// Check the stack top value whether the value is next address of the call instruction. 
		fn_info_t *fninfo = GetFunctionInfo(addr);
		if (fninfo == NULL) return;

		if (fninfo->name == "KiUserExceptionDispatcher") return;

		if (toADDRINT(buf) == current_callnextaddr) {

			*fout << toHex(current_calladdr - obf_img_saddr) << "\tcall\t";
		}
		else {
			*fout << toHex(current_calladdr - obf_img_saddr) << "\tgoto\t";
		}

		*fout << fninfo->module_name << '\t' << fninfo->name << endl;

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
		if (current_obf_fn_pos == obf_call_addrs.size()) {
			// when checking obfuscated call finished, prepare the end 
			isCheckAPIStart = false;
			isCheckAPIEnd = true;
			goto check_api_end;
		}
		pair<ADDRINT, ADDRINT> addrp = obf_call_addrs.at(current_obf_fn_pos++);
		ADDRINT calladdr = addrp.first;
		ADDRINT tgtaddr = addrp.second;
		
		// currently call instruction is of the form 'E8 __ __ __ __' which is 5 bytes
		// but originally it is 'FF 15 __ __ __ __' or 'FF 25 __ __ __ __' which is 6 bytes
		// so next instruction address is addr + 6
		current_calladdr = calladdr;
		current_callnextaddr = calladdr + 6;

		isCheckAPIStart = false;
		isCheckAPIRunning = true;


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
		// after checking obfuscated calls, find export calls and terminate.
		EXE64_CheckExportFunctions();
		((ofstream*)fout)->close();
		PIN_ExitProcess(-1);
	}

	prevaddr = addr;
}

// EXE INS memory write analysis function 
void EXE64_INS_APIDetect_MW_analysis(ADDRINT targetAddr)
{
	set_mwblock(targetAddr);
}


// API Detect executable trace instrumentation function
void EXE64_TRC_APIDetect_inst(TRACE trace, void *v)
{
	ADDRINT addr = TRACE_Address(trace);
	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)EXE64_TRC_APIDetect_analysis,
		IARG_CONTEXT,
		IARG_ADDRINT, addr,
		IARG_THREAD_ID,
		IARG_END);

	// instrument each memory read/write instruction
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			if (INS_Mnemonic(ins) == "XRSTOR") continue;

			if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins))
			{
				// record write addresses to detect OEP
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)EXE64_INS_APIDetect_MW_analysis,
					IARG_MEMORYWRITE_EA,
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
				if (oep == 0)
				{
					oep = addr;
					*fout << "OEP:" << toHex(oep - obf_img_saddr) << endl;
				}
			}
		}
		// near OEP is the address of the first call instruction 
		else {
			if (isCheckAPIStart || isCheckAPIRunning || isCheckAPIEnd) return;
			for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
				for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
					ADDRINT taddr = INS_Address(ins);
					if (taddr < obf_txt_saddr || taddr > obf_txt_eaddr) continue;
					if (INS_IsCall(ins)) {
						// oep = INS_Address(ins);
						oep = BBL_Address(bbl);
						*fout << "NEAR OEP:" << toHex(oep - obf_img_saddr) << endl;
						EXE64_FindAPICalls();
						isCheckAPIStart = true;
						return;
					}
				}
			}
		}
		return;
	}
}


// ========================================================================================================================
// API Detection Functions for x86
// ========================================================================================================================

// Check External Reference from main image address for x86
void CheckExportFunctions()
{
	size_t imgsize = obf_img_eaddr - obf_img_saddr;;
	UINT8 *buf = (UINT8*)malloc(imgsize);
	UINT8 *bufp;
	size_t idx;
	ADDRINT addr, target_addr, blk_addr;
	size_t num_fnaddrs, num_nonfnaddrs;
	ADDRINT iat_start_addr = 0, iat_size = 0;

	unsigned char* pc = reinterpret_cast<unsigned char*>(obf_img_saddr);
	
	// buf has executable memory image
	PIN_SafeCopy(buf, pc, imgsize);

	// skip alignment error
	if (obf_img_saddr % 0x1000) goto free_buf;

	if (isDebug)
	{
		*dout << "obfaddr size: " << obfaddr2fn.size() << endl;
		for (auto it = obfaddr2fn.begin(); it != obfaddr2fn.end(); it++)
		{
			*dout << toHex(it->first) << " -> " << it->second << endl;
		}
	
		*dout << "\n\nmemory dump" << endl;
		for (idx = 0; idx < imgsize; idx+= 4)
		{
			bufp = buf + idx;
			if (idx % 16 == 0) *dout << toHex(obf_img_saddr + idx) << ' ';
			*dout << toHex(MakeDWORD(bufp)) << ' ';			
			if (idx % 16 == 12) *dout << endl;
		}
	}
	
	// search for Import Address Table 	
	if (isDebug) *dout << "Searching for IAT " << endl;
	
	for (idx = 0; idx < obf_txt_eaddr - obf_txt_saddr; idx += 0x1000)
	{		
		blk_addr = obf_txt_saddr + idx;
		iataddr2obffnaddr.clear();		
		num_fnaddrs = 0;
		num_nonfnaddrs = 0;

		for (addr = blk_addr, bufp = buf + idx + (obf_txt_saddr - obf_img_saddr); 
			addr < blk_addr + 0x1000; 
			addr += sizeof(ADDRINT), bufp += sizeof(ADDRINT))
		{
			
			// target_addr : memory value at 'addr'						
			target_addr = MakeADDR(bufp);
			if (isDebug) *dout << toHex(addr) << ' ' << toHex(target_addr) << endl;

			// if target_addr is obfuscated function address
			if (obfaddr2fn.find(target_addr) != obfaddr2fn.end())
			{				
				iataddr2obffnaddr[addr] = target_addr;
				if (num_fnaddrs == 0) iat_start_addr = addr;
				num_fnaddrs++;

			}
			else if (GetFunctionInfo(target_addr) != NULL)
			{
				if (num_fnaddrs == 0) iat_start_addr = addr;
				num_fnaddrs++;
			}
			else if (target_addr != 0 && target_addr != 0xFFFFFFFF)
			{
				if (num_fnaddrs > 3) {
					num_nonfnaddrs++;
					if (num_nonfnaddrs > 3) {
						iat_size = (addr - iat_start_addr) - 16;
						goto found_iat;
					}
				}
				else {
					num_fnaddrs = 0;
					num_nonfnaddrs = 0;
					iat_start_addr = 0;
				}
			}
		}
	}

	// no IAT	
	goto call_modification;

found_iat:
	// record IAT deobfuscation information
	// We should modify IAT because of the following code pattern
	//
	// MOV ESI, DWORD [IAT entry address]
	// ...
	// CALL ESI
	// 
	if (iat_start_addr != 0) {
		*fout << "IAT START: " << toHex(iat_start_addr - obf_img_saddr) << endl;
		*fout << "IAT SIZE: " << toHex(iat_size * sizeof(ADDRINT)) << endl;
	}
	else {
		*fout << "IAT START: ?" << endl;
		*fout << "IAT SIZE: ?" << toHex(iat_size * sizeof(ADDRINT)) << endl;

	}
	for (auto it = iataddr2obffnaddr.begin(); it != iataddr2obffnaddr.end(); it++)
	{					
		ADDRINT srcaddr = it->first;
		ADDRINT dstaddr = it->second;
		fn_info_t *dstfn = obfaddr2fn[dstaddr];
		if (dstfn == NULL) *fout << toHex(srcaddr - obf_img_saddr) << "\taddr " << toHex(dstaddr) << endl;
		*fout << toHex(srcaddr - obf_img_saddr) << "\taddr " << dstfn->module_name << '\t' << dstfn->name << endl;
	}

call_modification:

	// search for address modification in program
	for (bufp = buf, idx = 0; idx < imgsize - 4; idx++, bufp++) 
	{		
		// CALL r/m32 (FF 1F __ __ __ __)
		// is patched by Themida into
		// CALL rel32; NOP (E8 __ __ __ __ 90)
		if (*bufp == 0xE8 && bufp[5] == 0x90)
		{
			
			addr = obf_img_saddr + idx;
			target_addr = addr + 5 + MakeADDR1(bufp);

			if (obfaddr2fn.find(target_addr) != obfaddr2fn.end())
			{
				fn_info_t *fn = obfaddr2fn[target_addr];				

				string modstr = fn->module_name;

				if (modstr != "kernel32.dll" &&
					modstr != "user32.dll" &&
					modstr != "advapi32.dll" && 
					modstr != "ntdll.dll")
					continue;
				
				string fnstr = fn->name;				
				string reladdr = toHex(addr - obf_img_saddr); 
				*fout << reladdr << "\tcall " << modstr << '\t' << fnstr << endl;
			}
		}
	}

free_buf:
	free(buf);

}

// API detect analysis function
void EXE_TRC_APIDetect_analysis(ADDRINT addr, THREADID threadid)
{
	if (threadid != 0) return;

	//if (debugger_attach_wait_time > 0 && isDetach)
	//{
	//	// wait for a debugger to attach this process
	//	*fout << "waiting debugger to attach" << endl;
	//	PIN_Sleep(debugger_attach_wait_time);
	//	// PIN_Detach();
	//	return;
	//}

	if (isDebug)
	{
		fn_info_t *info1 = GetFunctionInfo(addr);
		fn_info_t *info2 = GetFunctionInfo(prevaddr);

		if ((addr >= obf_img_saddr && addr < obf_img_eaddr)) {
			*dout << "E:" << toHex(addr);
			if (info1) *dout << ' ' << info1->module_name << ":" << info1->name;
			*dout << endl;
		}
		
		if (info1 != NULL && info2 == NULL && (addr > obf_img_eaddr || addr < obf_img_saddr))
		{
			*dout << "call : " << info1->name << endl;
		}

	}
	prevaddr = addr;
}

// DLL trace analysis function 
// check whether unpacking process end
void DLL_TRC_analysis(ADDRINT addr, THREADID threadid)
{
	if (threadid != 0) return;

	if (addr == obf_entry_addr) {
		is_unpack_started = true;
	}

	if (is_unpack_started && addr >= loader_saddr && addr < loader_eaddr)
	{
		CheckExportFunctions();
		((ofstream*)fout)->close();
		PIN_ExitProcess(-1);
	}

	prevaddr = addr;
}


// EXE trace instrumentation function
void EXE_TRC_APIDetect_inst(TRACE trace, void *v)
{
	ADDRINT addr = TRACE_Address(trace);
	
	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)EXE_TRC_APIDetect_analysis,
		IARG_ADDRINT, addr,
		IARG_THREAD_ID,
		IARG_END);

	if (isDebug && addr >= obf_img_saddr && addr < obf_img_eaddr) {
		*dout << "Trace:" << toHex(addr) << endl;
	}
	// instrument each memory read/write instruction
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			ADDRINT taddr = INS_Address(ins);
			// if (INS_Mnemonic(ins) == "XRSTOR") continue;
			if (INS_IsMemoryRead(ins) && !INS_IsStackRead(ins))
			{
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)EXE_INS_APIDetect_MR_analysis,
					IARG_INST_PTR,
					IARG_MEMORYREAD_SIZE,
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_END);
			}

			if (INS_HasMemoryRead2(ins) && !INS_IsStackRead(ins))
			{
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)EXE_INS_APIDetect_MR_analysis,
					IARG_INST_PTR,
					IARG_MEMORYREAD_SIZE,
					IARG_MEMORYREAD2_EA,
					IARG_THREAD_ID,
					IARG_END);
			}

			if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins))
			{
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)EXE_INS_APIDetect_MW_analysis,
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
						oep = BBL_Address(bbl);
						*fout << "NEAR OEP:" << toHex(oep - obf_img_saddr) << endl;
						if (sizeof(ADDRINT) == 4) CheckExportFunctions();
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

// EXE INS memory write analysis function 
void EXE_INS_APIDetect_MW_analysis(CONTEXT *ctxt, ADDRINT ip, ADDRINT nextip, size_t mSize, ADDRINT targetAddr, THREADID threadid)
{
	set_mwblock(targetAddr);

	if (current_obf_fn == NULL) return;
	
	mod_info_t *md = GetModuleInfo(targetAddr);
	if (md != NULL) return;
	if (targetAddr >= obf_img_saddr && targetAddr < obf_img_eaddr) return;

	for (UINT i = 0; i < mSize; i++)
	{
		obfaddr2fn[targetAddr + i] = current_obf_fn;
	}

	if (isDebug) {
		fn_info_t *finfo = GetFunctionInfo(targetAddr);
		if (finfo != NULL)
		{
			*dout << "API Function Write: " << *current_obf_fn << endl;
		}
	}
}

// EXE INS memory read analysis function 
void EXE_INS_APIDetect_MR_analysis(ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid)
{
	fn_info_t *finfo = GetFunctionInfo(targetAddr);
	if (finfo == NULL) return;
	current_obf_fn = finfo;
}

// EXE INS memory write analysis function 
void DLL_INS_APIDetect_MW_analysis(ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid)
{
	set_mwblock(targetAddr);

	if (current_obf_fn == NULL) return;
	if (targetAddr >= obf_img_saddr && targetAddr < obf_img_eaddr) return;

	for (UINT i = 0; i < mSize; i++)
	{
		obfaddr2fn[targetAddr + i] = current_obf_fn;
	}
}

// EXE INS memory read analysis function 
void DLL_INS_APIDetect_MR_analysis(ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid)
{
	fn_info_t *finfo = GetFunctionInfo(targetAddr);
	if (finfo == NULL) return;
	current_obf_fn = finfo;
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
	PIN_GetLock(&lock, threadid + 1);
	*fout << toHex(ip) << " W:" << toHex(targetAddr) << " S:" << mSize << ' ' << GetAddrInfo(targetAddr) << ' ' << asmcode_m[ip] << endl;
	PIN_ReleaseLock(&lock);
}

// memory trace memory read analysis function
void EXE_INS_Memtrace_MR_analysis(ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid)
{
	PIN_GetLock(&lock, threadid + 1);
	*fout << toHex(ip) << " R:" << toHex(targetAddr) << " S:" << mSize << ' ' << GetAddrInfo(targetAddr) << ' ' << asmcode_m[ip] << endl;
	PIN_ReleaseLock(&lock);
}



// ========================================================================================================================
// Instruction Trace Functions 
// ========================================================================================================================

// Instruction trace analysis function for executables
void EXE_Trace_InsTrc_Analysis(ADDRINT ip, THREADID threadid)
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

	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)EXE_Trace_InsTrc_Analysis,
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
// Common Callbacks
// ========================================================================================================================

// IMG instrumentation function for EXE files
void EXE_IMG_inst(IMG img, void *v)
{
	string imgname = IMG_Name(img);

	size_t pos = imgname.rfind("\\") + 1;
	imgname = imgname.substr(pos);

	if (IMG_IsMainExecutable(img)) {
		*fout << "NAME:" << imgname << endl;
	}

	TO_LOWER(imgname);

	mod_info_t *dllinfo = NULL;

	if (module_info_m.find(imgname) == module_info_m.end())
	{
		string name = imgname;
		ADDRINT saddr = IMG_LowAddress(img);
		ADDRINT eaddr = IMG_HighAddress(img);

		dllinfo = new mod_info_t(name, saddr, eaddr);
		module_info_m[name] = dllinfo;

		if (IMG_IsMainExecutable(img))
		{
			obf_img_saddr = saddr;
			obf_img_eaddr = eaddr;

			// modify tracing start address according to memory loaded address of the executable file
			if (instrc_saddr != 0) instrc_saddr += obf_img_saddr;
			if (instrc_eaddr != 0) instrc_eaddr += obf_img_saddr;

			// *fout << toHex(instrc_saddr) << ' ' << toHex(instrc_eaddr) << endl;
			SEC sec = IMG_SecHead(img);

			obf_txt_saddr = SEC_Address(sec);
			obf_txt_eaddr = obf_txt_saddr + SEC_Size(sec);

			// for 64 bit application check IAT candidate first
			if (sizeof(ADDRINT) == 8) {
				EXE64_CheckExportArea(1);
			}
		}
		if (isDebug) *dout << name << '\t' << toHex(saddr) << "," << toHex(eaddr) << endl;
	}
	else
	{
		return;
	}
	
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		string secname = SEC_Name(sec);
		ADDRINT saddr = SEC_Address(sec);
		ADDRINT eaddr = saddr + SEC_Size(sec);
		sec_info_t *secinfo = new sec_info_t(imgname, secname, saddr, eaddr);
		dllinfo->sec_infos.push_back(secinfo);
		if (isDebug) *dout << '\t' << secname << '\t' << toHex(saddr) << "," << toHex(eaddr) << endl;

		if (SEC_Name(sec) == ".text")
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

				if (rtnname == "DbgBreakUiRemoteBreakin" || rtnname == "DbgBreakPoint") {
					for (ADDRINT addr = saddr; addr < saddr + 8; addr++)
						anti_attach_address_set.insert(addr);
				}
			}
		}
	}
}

// IMG instrumentation function for DLL files
void DLL_IMG_inst(IMG img, void *v)
{
	string imgname = IMG_Name(img);
	ADDRINT module_addr = 0;
	bool isWrappedDLL = false;

	TO_LOWER(imgname);
	size_t pos = imgname.rfind("\\") + 1;
	imgname = imgname.substr(pos);

	module_addr = IMG_Entry(img);

	if (imgname == dll_name)
	{
		obf_entry_addr = module_addr;
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
		
		SEC sec = IMG_SecHead(img);
		obf_txt_saddr = SEC_Address(sec);
		obf_txt_eaddr = obf_txt_saddr + SEC_Size(sec);
	}

	// for 64 bit application check IAT candidate first
	if ((IMG_IsMainExecutable(img) || imgname == dll_name) && sizeof(ADDRINT) == 8) {
		EXE64_CheckExportArea(1);
	}

	dllinfo = new mod_info_t(name, saddr, eaddr);
	module_info_m[name] = dllinfo;

	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		string secname = SEC_Name(sec);
		ADDRINT saddr = SEC_Address(sec);
		ADDRINT eaddr = saddr + SEC_Size(sec);
		sec_info_t *secinfo = new sec_info_t(imgname, secname, saddr, eaddr);
		dllinfo->sec_infos.push_back(secinfo);		

		if (SEC_Name(sec) == ".text")
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

	}
}

// TRACE instrumentation function for DLL files
void DLL_TRC_inst(TRACE trace, void *v)
{
	ADDRINT addr = TRACE_Address(trace);

	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)DLL_TRC_analysis,
		IARG_ADDRINT, addr,
		IARG_THREAD_ID,
		IARG_CONTEXT,
		IARG_END);
}

void DLL64_TRC_inst(TRACE trace, void *v)
{
	ADDRINT addr = TRACE_Address(trace);

	TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)DLL64_TRC_analysis,
		IARG_CONTEXT,
		IARG_ADDRINT, addr,
		IARG_THREAD_ID,
		IARG_END);

	if (addr == obf_entry_addr) {
		is_unpack_started = true;
	}

	if (is_unpack_started && addr >= loader_saddr && addr < loader_eaddr)
	{
		EXE64_FindAPICalls();
		isCheckAPIStart = true;
	}
}

// DLL trace analysis function 
// check whether unpacking process end
void DLL64_TRC_analysis(CONTEXT *ctxt, ADDRINT addr, THREADID threadid)
{
	if (threadid != 0) return;

	if (isCheckAPIRunning) {
		// if obfuscated API checking is started and 
		// if the trace is in another section
		// then here is the obfuscated instructions that resolve 'call API_function'
		// These obfuscated instructions end by 'RET' instruction 
		// that jumps into API function code

		UINT8 buf[8];
		ADDRINT stkptr = PIN_GetContextReg(ctxt, REG_STACK_PTR);
		PIN_SafeCopy(buf, (VOID*)stkptr, 8);

		if (addr > obf_txt_eaddr && addr < obf_img_eaddr) {
			// DO NOTHING
			return;
		}

		// if the trace in in API function
		// then here is the API function. 
		// Check the stack top value whether the value is next address of the call instruction. 
		fn_info_t *fninfo = GetFunctionInfo(addr);
		if (fninfo == NULL) return;
		if (fninfo->name == "KiUserExceptionDispatcher") return;

		if (toADDRINT(buf) == current_callnextaddr) {

			*fout << toHex(current_calladdr - obf_img_saddr) << "\tcall\t";
		}
		else {
			*fout << toHex(current_calladdr - obf_img_saddr) << "\tgoto\t";
		}

		*fout << fninfo->module_name << '\t' << fninfo->name << endl;

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
		if (current_obf_fn_pos == obf_call_addrs.size()) {
			// when checking obfuscated call finished, prepare the end 
			isCheckAPIStart = false;
			isCheckAPIEnd = true;
			goto check_api_end;
		}
		pair<ADDRINT, ADDRINT> addrp = obf_call_addrs.at(current_obf_fn_pos++);
		ADDRINT calladdr = addrp.first;
		ADDRINT tgtaddr = addrp.second;

		// currently call instruction is of the form 'E8 __ __ __ __' which is 5 bytes
		// but originally it is 'FF 15 __ __ __ __' or 'FF 25 __ __ __ __' which is 6 bytes
		// so next instruction address is addr + 6
		current_calladdr = calladdr;
		current_callnextaddr = calladdr + 6;

		isCheckAPIStart = false;
		isCheckAPIRunning = true;

		current_obf_fn_addr = tgtaddr;

		// change IP to obfuscated function call target. 
		PIN_SetContextReg(ctxt, REG_INST_PTR, calladdr);
		PIN_ExecuteAt(ctxt);
	}

check_api_end:
	if (isCheckAPIEnd) {
		// after checking obfuscated calls, find export calls and terminate.
		EXE64_CheckExportFunctions();
		((ofstream*)fout)->close();
		PIN_ExitProcess(-1);
	}
	prevaddr = addr;
}

// Fix IAT after run-until-API methods
void DLL64_FixIAT() {

}

// Find API Calls (~= External References) from main image address for x86/64 DLL
void DLL_FindAPICalls()
{
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
		// is patched by Themida64 into
		// CALL rel32; db 00 (E8 __ __ __ __ ; 00)
		if (buf[idx] == 0xE8 && buf[idx + 5] == 0x00)
		{
			addr = obf_txt_saddr + idx;
			target_addr = addr + 5 + buf[idx + 1] + (buf[idx + 2] << 8) + (buf[idx + 3] << 16) + (buf[idx + 4] << 24);
			sec_info_t *current_section = GetSectionInfo(addr);
			sec_info_t *target_section = GetSectionInfo(target_addr);

			if (current_section == NULL || target_section == NULL) continue;

			// obfuscated call target is selected by 
			// - call targets into other section of the main executables
			if (current_section->module_name == target_section->module_name &&
				current_section->saddr != target_section->saddr) {
				// *fout << "Obfuscated Call : " << toHex(addr) << " -> " << toHex(target_addr) << endl;
				obf_call_addrs.push_back(make_pair(addr, target_addr));
			}
		}
	}
	free(buf);
}


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

// dll instruction instrumentation function
void DLL_INS_inst(INS ins, void *v)
{
	// get current address
	ADDRINT addr = INS_Address(ins);

	// skip external modules
	// only watch dll file
	mod_info_t *minfo = GetModuleInfo(addr);

	if (!is_unpack_started) return;
	if (!isAPIDetect) return;

	// Iterate over each memory operand of the instruction.
	size_t memOperands = INS_MemoryOperandCount(ins);
	for (size_t memOp = 0; memOp < memOperands; memOp++)
	{
		// Check every memory operand except stack accessing operands
		// Note that in some architectures a single memory operand can be 
		// both read and written (for instance incl (%eax) on IA-32)
		// In that case we instrument it once for read and once for write.

		if (INS_Mnemonic(ins) == "XRSTOR") continue;

		if (INS_MemoryOperandIsRead(ins, (UINT32)memOp) && !INS_IsStackRead(ins))
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)DLL_INS_APIDetect_MR_analysis,
				IARG_INST_PTR,
				IARG_MEMORYWRITE_SIZE,
				IARG_MEMORYOP_EA, memOp,
				IARG_THREAD_ID,
				IARG_END);
		}
		if (INS_MemoryOperandIsWritten(ins, (UINT32)memOp) && !INS_IsStackWrite(ins))
		{
			INS_InsertPredicatedCall(
				ins, IPOINT_BEFORE, (AFUNPTR)DLL_INS_APIDetect_MW_analysis,
				IARG_INST_PTR,
				IARG_MEMORYWRITE_SIZE,
				IARG_MEMORYOP_EA, memOp,
				IARG_THREAD_ID,
				IARG_END);
		}
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
			if (INS_Mnemonic(ins) == "XRSTOR") continue;

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
				if (oep == 0)
				{
					oep = addr;
					*fout << "OEP:" << toHex(oep - obf_img_saddr) << endl;
				}
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
						if (sizeof(ADDRINT) == 4) CheckExportFunctions();
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
    
	string outputFileName = KnobOutputFile.Value();	
	if (outputFileName == "result.txt")
	{
		outputFileName = string(argv[argc - 1]);
		outputFileName += ".txt";
	}	
	
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
	instrc_eaddr = AddrintFromString(KnobTraceEndAddr.Value());

	PIN_InitSymbols();

	// Register Analysis routines to be called when a thread begins/ends
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	// Register function to be called to instrument traces
	if (isDLLAnalysis) {
		if (sizeof(ADDRINT) == 4) {
			TRACE_AddInstrumentFunction(DLL_TRC_inst, 0);
			IMG_AddInstrumentFunction(DLL_IMG_inst, 0);
			INS_AddInstrumentFunction(DLL_INS_inst, 0);
		}
		else {
			TRACE_AddInstrumentFunction(DLL64_TRC_inst, 0);
			IMG_AddInstrumentFunction(DLL_IMG_inst, 0);
		}
	}
	else {

		if (isMemTrace) TRACE_AddInstrumentFunction(EXE_TRC_MemTrace_inst, 0);
		
		if (isAPIDetect) {
			if (sizeof(ADDRINT) == 4) {
				// for 32 bit executable file
				TRACE_AddInstrumentFunction(EXE_TRC_APIDetect_inst, 0);
			}
			else {
				// for 64 bit executable file 
				TRACE_AddInstrumentFunction(EXE64_TRC_APIDetect_inst, 0);
			}
		}

		if (isOEPDetect) {
			TRACE_AddInstrumentFunction(EXE_TRC_OEPDetect_inst, 0);
		}

		if (instrc_saddr != 0) {
			TRACE_AddInstrumentFunction(EXE_TRC_InsTrc_Inst, 0);
		}

		IMG_AddInstrumentFunction(EXE_IMG_inst, 0);
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
