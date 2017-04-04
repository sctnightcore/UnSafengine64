// CV Analyzer 
// Author: seogu.choi@gmail.com
// Date: 2015.4.25. ~ 

#include "CVPinAnalyzer.h"

using namespace std;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "result.txt", "specify file name for the result");
KNOB<bool> KnobMemoryTrace(KNOB_MODE_WRITEONCE, "pintool", "mem", "1", "specify whether to record memory trace or not");
KNOB<bool> KnobInstructionTrace(KNOB_MODE_WRITEONCE, "pintool", "ins", "1", "instruction trace");
KNOB<string> KnobTraceStartAddr(KNOB_MODE_WRITEONCE, "pintool", "saddr", "0", "instruction trace start address");
KNOB<string> KnobTraceEndAddr(KNOB_MODE_WRITEONCE, "pintool", "eaddr", "0", "instruction trace end address");
KNOB<bool> KnobTraceDetail(KNOB_MODE_WRITEONCE, "pintool", "trdetail", "0", "instruction trace with dll");

KNOB<bool> KnobDumpCode(KNOB_MODE_WRITEONCE, "pintool", "dumpcode", "0", "dump code");
KNOB<bool> KnobFindHandlerAddress(KNOB_MODE_WRITEONCE, "pintool", "1", "1", "1st step: find handler candidate addresses");


// ========================================================================================================================
// Memory Trace Functions 
// ========================================================================================================================

// memory trace analysis function
void EXE_TRC_Memtrc_analysis(ADDRINT addr, THREADID threadid)
{	
	mod_info_t *minfo = GetModuleInfo(addr);
	if (minfo == NULL) return;
	if (minfo->isDLL()) {
		fn_info_t *finfo = GetFunctionInfo(addr);
		if (finfo->saddr != addr) return;
	}
	string msg = "";
	if (rev_hdl_addr_m.find(addr) != rev_hdl_addr_m.end()) {
		msg = " HDL";
	}

	PIN_GetLock(&lock, threadid + 1);
	*fout << toHex(addr) << ' ' << "E:" << threadid << " " << GetAddrInfo(addr) << msg << endl;	
	PIN_ReleaseLock(&lock);
}

// memory trace instrumentation function
void EXE_TRC_MemTrace_Inst(TRACE trace, void *v)
{
	ADDRINT addr = TRACE_Address(trace);

	// skip dll module
	mod_info_t *minfo = GetModuleInfo(addr);
	mod_info_t *prevminfo = prevmod;
	prevmod = minfo;
	if (minfo == NULL) return;
	if (minfo->isDLL() && prevminfo != NULL && prevminfo->isDLL()) return;

	// avoid duplicated execution trace
	if (!isInsTrace)
		TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)EXE_TRC_Memtrc_analysis,
			IARG_ADDRINT, addr,
			IARG_THREAD_ID,
			IARG_END);

	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{

			// for efficiency exclude CMP and SCASB instructions
			if (INS_Opcode(ins) == XED_ICLASS_CMP ||
				INS_Opcode(ins) == XED_ICLASS_SCASB ||
				INS_Opcode(ins) == XED_ICLASS_SCASW ||
				INS_Opcode(ins) == XED_ICLASS_SCASD) continue;

			ADDRINT addr = INS_Address(ins);
			string disasm_code = INS_Disassemble(ins);
			asmcode_m[addr] = disasm_code;
			// LOG(disasm_code + '\n');
			if (analysis_step == 1) {
				// In order to find handler addresses, 
				// we investigate 'add dword ptr [reg], reg' type instructions. 
				// These instructions is to adjusting handler addresses due to ASLR. 
				// These type of address adjusting appears in Code Virtualizer 2.x versions. 
				if (disasm_code.find("add dword ptr") != string::npos) {
					REG op1reg = INS_OperandReg(ins, 1);
					if (op1reg != REG_INVALID_) {
						op_cache_m[addr] = op1reg;
					}
				}
			}
 			
			if (INS_IsMemoryRead(ins))
			{
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)EXE_INS_Memtrace_MR_analysis,
					IARG_CONTEXT, 
					IARG_INST_PTR,
					IARG_MEMORYREAD_SIZE,
					IARG_MEMORYREAD_EA,
					IARG_THREAD_ID,
					IARG_BOOL, INS_IsStackRead(ins), 
					IARG_END);
			}

			if (INS_HasMemoryRead2(ins) && !INS_IsStackRead(ins))
			{
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)EXE_INS_Memtrace_MR_analysis,
					IARG_CONTEXT,
					IARG_INST_PTR,
					IARG_MEMORYREAD_SIZE,
					IARG_MEMORYREAD2_EA,
					IARG_THREAD_ID,
					IARG_BOOL, INS_IsStackRead(ins),
					IARG_END);
				// *fout << toHex(addr) << ' ' << INS_Disassemble(ins) << endl;
			}

			if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins))
			{
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)EXE_INS_Memtrace_MW_analysis,
					IARG_CONTEXT,
					IARG_INST_PTR,
					IARG_MEMORYWRITE_SIZE,
					IARG_MEMORYWRITE_EA,
					IARG_THREAD_ID,
					IARG_BOOL, INS_IsStackWrite(ins),
					IARG_END);
				INS_InsertPredicatedCall(
					ins, IPOINT_AFTER, (AFUNPTR)EXE_INS_Memtrace_MW_after_analysis,
					IARG_CONTEXT,
					IARG_MEMORYWRITE_SIZE,
					IARG_THREAD_ID,
					IARG_BOOL, INS_IsStackWrite(ins),
					IARG_END);
			}
		}
	}
}

// shared global variable across memory read before and after
ADDRINT mem_write_addr, mem_read_addr;
stringstream delayed_msg;
// string delayed_msg;

// memory trace memory write analysis function
void EXE_INS_Memtrace_MW_analysis(CONTEXT *ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack)
{
	mem_write_addr = targetAddr;
	if (is_stack && (targetAddr < obf_img_saddr || targetAddr >= obf_img_eaddr)) {
		return;
	}

	delayed_msg.clear();
	bool isFound = false;
	if (op_cache_m.find(ip) != op_cache_m.end()) {
		REG op1reg = op_cache_m[ip];

		ADDRINT base_addr = PIN_GetContextReg(ctxt, op1reg);
		if (base_addr == obf_img_saddr) {
			// UINT8 buf[sizeof(ADDRINT)];
			PIN_SafeCopy(buf, (VOID*)targetAddr, sizeof(ADDRINT));
			ADDRINT haddr = toADDRINT(buf);
			hdl_addr_m[targetAddr] = haddr + base_addr;
			rev_hdl_addr_m[haddr + base_addr] = targetAddr;
			// delayed_msg = "HDL";
			isFound = true;
		}
	}

	delayed_msg << toHex(ip) << " W:" << toHex(targetAddr) << " S:" << mSize;
	if (isFound) delayed_msg << " HDL";
	delayed_msg << ' ';

	// PIN_GetLock(&lock, threadid + 1);
	// *fout << toHex(ip) << "\tW:" << toHex(targetAddr) << "\t" << mSize << '\t' << GetAddrInfo(targetAddr) << '\t' << asmcode_m[ip] << msg;
	// *fout << toHex(ip) << " W:" << toHex(targetAddr) << " S:" << mSize << ' ' << msg;	
	// PIN_ReleaseLock(&lock);
}

// memory trace memory write analysis function
void EXE_INS_Memtrace_MW_after_analysis(CONTEXT *ctxt, size_t mSize, THREADID threadid, BOOL is_stack)
{
	if (is_stack && (mem_write_addr < obf_img_saddr || mem_write_addr >= obf_img_eaddr)) return;

	string msg = "";
	// UINT8 buf[sizeof(ADDRINT)];
	PIN_SafeCopy(buf, (VOID*)mem_write_addr, mSize);
	ADDRINT mem_value = buf2val(buf, mSize);		
	ADDRINT ebp_val = PIN_GetContextReg(ctxt, REG_EBP);

	ADDRDELTA diff = mem_write_addr - ebp_val;
	if (ebp_val >= obf_img_saddr && ebp_val < obf_img_eaddr && diff >= 0 && diff <= 0xFF) {
		// *fout << "EBP:" << toHex(ebp_val) << " DIFF:" << toHex1(diff) << ' ';
		delayed_msg << "EBP:" << toHex(ebp_val) << " DIFF:" << toHex1(diff) << ' ';
	}

	delayed_msg <<  "V:" << StringHex(mem_value, mSize * 2, false);
	
	
	// *fout << "V:" << StringHex(mem_value, mSize * 2, false);
	
	PIN_GetLock(&lock, threadid + 1);
	*fout << delayed_msg.str() << endl;
	PIN_ReleaseLock(&lock);
}


// memory trace memory read analysis function
void EXE_INS_Memtrace_MR_analysis(CONTEXT *ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack)
{
	if (is_stack && (targetAddr < obf_img_saddr || targetAddr >= obf_img_eaddr)) return;

	string msg = "";
	//if (hdl_addr_m.find(targetAddr) != hdl_addr_m.end()) {
	//	msg = "HDL:" + toHex(hdl_addr_m[targetAddr]) + ' ';
	//	// msg += " EBP:" + toHex(PIN_GetContextReg(ctxt, REG_STACK_PTR));
	//}

	// UINT8 buf[sizeof(ADDRINT)];	

	PIN_SafeCopy(buf, (VOID*)targetAddr, mSize);
	ADDRINT mem_value = buf2val(buf, mSize);
	ADDRINT ebp_val = PIN_GetContextReg(ctxt, REG_EBP);
	ADDRDELTA diff = targetAddr - ebp_val;

	if (ebp_val >= obf_img_saddr && ebp_val < obf_img_eaddr && diff >= 0 && diff <= 0xFF) {
		// msg += "\tEBP:" + toHex(ebp_val) + "\tdiff:" + toHex1(diff);
		msg += "EBP:" + toHex(ebp_val) + " DIFF:" + toHex1(diff) + ' ';
	}

	// msg += "\tVAL:" + toHex(mem_value);
	msg += "V:" + StringHex(mem_value, mSize*2, false);

	PIN_GetLock(&lock, threadid + 1);
	// *fout << toHex(ip) << "\tR:" << toHex(targetAddr) << "\t" << mSize << '\t' << GetAddrInfo(targetAddr) << '\t' << asmcode_m[ip] << msg << endl;
	*fout << toHex(ip) << " R:" << toHex(targetAddr) << " S:" << mSize << ' ' << msg << endl;

	PIN_ReleaseLock(&lock);
}

// ========================================================================================================================
// Instruction Trace Functions -[
// ========================================================================================================================

// Instruction trace analysis function for executables
void EXE_Trc_ana(ADDRINT addr, THREADID threadid) {

	// skip before tracing start
	if (!isInsTrcReady) {
		prevaddr = addr;
		prevmod = GetModuleInfo(addr);
		return;
	}

	// skip logging an API function called from another API function
	if ((addr < obf_img_saddr || addr >= obf_img_eaddr) && (prevaddr < obf_img_saddr || prevaddr >= obf_img_eaddr)) {
		prevaddr = addr;
		prevmod = GetModuleInfo(addr);
		return;
	}
	
	// log trace
	
	*fout << toHex(addr) << ' ' << threadid << " E:" << GetAddrInfo(addr) << endl;
	prevaddr = addr;
	prevmod = GetModuleInfo(addr);

	if (isInsTrcReady) {
		mod_info_t *modinfo = GetModuleInfo(addr);

		if (trace_cache_m.find(addr) == trace_cache_m.end()) {
			*fout << "no trace cache at " << toHex(addr) << endl;
			return;
		}

		for (auto it = trace_cache_m[addr]->begin(); it != trace_cache_m[addr]->end(); it++) {
			ADDRINT addr = *it;
			if (addr == instrc_saddr) {
				isInsTrcOn = true;
				*fout << "instruction tracing started" << endl;
			}

			if (isInsTrcOn) {
				if (asmcode_m.find(addr) != asmcode_m.end())
					*fout << toHex(addr) << ' ' << asmcode_m[addr] << endl;
				else
					*fout << toHex(addr) << " error" << endl;
			}			
		}
	}
}


// Change instruction pointer to a specified address
void EXE_IPChange_ana(CONTEXT *ctxt, ADDRINT addr) {
	PIN_SetContextReg(ctxt, REG_INST_PTR, addr);
	PIN_ExecuteAt(ctxt);
}


// exit function
void EXE_Exit_ana() {	
	*fout << "Tracing End" << endl;
	PIN_ExitApplication(-1);	
}

// instruction log function
void EXE_Ins_ana(INS ins, ADDRINT addr) {	
	*fout << toHex(addr) << ' ' << asmcode_m[addr] << endl;
}

// Trace instrumentation function for executable file instruction trace
void EXE_Trc_ins(TRACE trc, void *v)
{
	ADDRINT addr = TRACE_Address(trc);

	TRACE_InsertCall(trc, IPOINT_BEFORE, (AFUNPTR)EXE_Trc_ana,
		IARG_ADDRINT, addr,
		IARG_THREAD_ID,
		IARG_END);

	if (addr == 0x4017ed) {
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
			for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				ADDRINT insaddr = INS_Address(ins);
				*fout << "Checking address " << toHex(insaddr) << endl;
				if (insaddr == 0x4017f0) {
					*fout << "Altering normal control flow" << endl;
					INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)EXE_IPChange_ana, IARG_CONTEXT, IARG_ADDRINT, 0x401806, IARG_END);
				}
			}
		}
	}

	// check exit condition
	if (instrc_eaddr >= addr && instrc_eaddr < addr + TRACE_Size(trc)) {
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
			for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				ADDRINT insaddr = INS_Address(ins);				
				if (insaddr == instrc_eaddr) {					
					INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EXE_Exit_ana, IARG_END);
				}
			}
		}
	}

	// check whether the instruction trace start address is contained in this trace
	if (instrc_saddr >= addr && instrc_saddr < addr + TRACE_Size(trc)) {
		*fout << "Tracing Start" << endl;
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
			for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				ADDRINT insaddr = INS_Address(ins);
				*fout << "Checking address " << toHex(insaddr) << endl;
				if (insaddr == 0x4017f0) {
					*fout << "Altering normal control flow" << endl;
					INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)EXE_IPChange_ana, IARG_CONTEXT, IARG_ADDRINT, 0x401806, IARG_END);
				}
			}
		}
		isInsTrcReady = true;
	}

	if (!isInsTrcReady) return;

	// trace only main image
	if (addr < obf_img_saddr || addr >= obf_img_eaddr) return;

	// skip dll module
	mod_info_t *minfo = GetModuleInfo(addr);
	if (minfo->isDLL()) return;
	
	if (trace_cache_m.find(addr) == trace_cache_m.end()) {
		trace_cache_m[addr] = new vector<ADDRINT>;
	}

	// when IP moves from text section to virtualized section, 
	// dump virtualized section

	if (isDumpCode) {
		if (prevaddr >= obf_txt_saddr && prevaddr < obf_txt_eaddr &&
			(addr < obf_txt_saddr || addr >= obf_txt_eaddr)) {
			sec_info_t *secinfo = GetSectionInfo(addr);

			size_t section_size = secinfo->eaddr - secinfo->saddr;

			UINT8 *vsection_dmp = (UINT8*)malloc(section_size);	// code cache buffer size is 1KB
			PIN_SafeCopy(vsection_dmp, (VOID*)secinfo->saddr, secinfo->eaddr - secinfo->saddr);

			*fout << toHex(addr) << " D:[" << toHex(secinfo->saddr) << ',' << toHex(secinfo->eaddr) << "] ";
			for (size_t i = 0; i < section_size; i++) {
				*fout << toHex1(vsection_dmp[i]);
			}
			*fout << endl;
		}

	}

	// check visiting addresses
	if (trace_visited_s.find(addr) == trace_visited_s.end()) {
		trace_visited_s.insert(addr);
		//USIZE size = TRACE_Size(trc);
		//PIN_SafeCopy(buf, (VOID*)addr, size);
		//for (size_t i = 0; i < size; i++) {
		//	*fout << toHex1(buf[i]);
		//}
		//*fout << endl;
	}

	for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			ADDRINT insaddr = INS_Address(ins);
			//if (insaddr == instrc_saddr) {
			//	*fout << "found trace start address" << endl;
			//	isInsTrcReady = true;
			//}
			//asmcode_m[insaddr] = INS_Disassemble(ins);
			//trace_cache_m[addr]->push_back(insaddr);
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EXE_Ins_ana, IARG_ADDRINT, insaddr, IARG_END);
			asmcode_m[insaddr] = INS_Disassemble(ins);
		}
	}

	//TRACE_InsertCall(trc, IPOINT_BEFORE, (AFUNPTR)EXE_Trc_ana,
	//	IARG_ADDRINT, addr,
	//	IARG_THREAD_ID,
	//	IARG_END);
}

// Trace instrumentation function for executable file instruction trace
void EXE_TRC_InsTrc_Inst(TRACE trc, void *v)
{
	ADDRINT addr = TRACE_Address(trc);
	
	// trace only main image
	if (addr < obf_img_saddr || addr >= obf_img_eaddr) return;
	
	// skip dll module
	mod_info_t *minfo = GetModuleInfo(addr);
	if (minfo->isDLL()) return;

	// when IP moves from text section to virtualized section, 
	// dump virtualized section
	if (trace_cache_m.find(addr) == trace_cache_m.end()) {
		trace_cache_m[addr] = new vector<ADDRINT>;
		if (isDumpCode) {
			if (prevaddr >= obf_txt_saddr && prevaddr < obf_txt_eaddr &&
				(addr < obf_txt_saddr || addr >= obf_txt_eaddr)) {
				sec_info_t *secinfo = GetSectionInfo(addr);

				size_t section_size = secinfo->eaddr - secinfo->saddr;

				UINT8 *vsection_dmp = (UINT8*)malloc(section_size);	// code cache buffer size is 1KB
				PIN_SafeCopy(vsection_dmp, (VOID*)secinfo->saddr, secinfo->eaddr - secinfo->saddr);

				*fout << toHex(addr) << " D:[" << toHex(secinfo->saddr) << ',' << toHex(secinfo->eaddr) << "] ";
				for (size_t i = 0; i < section_size; i++) {
					*fout << toHex1(vsection_dmp[i]);
				}
				*fout << endl;
			}
		}
	}	

	// check visiting addresses
	if (trace_visited_s.find(addr) == trace_visited_s.end()) {
		trace_visited_s.insert(addr);
		USIZE size = TRACE_Size(trc);		
		PIN_SafeCopy(buf, (VOID*)addr, size);
		for (size_t i = 0; i < size; i++) {
			*fout << toHex1(buf[i]);
		}
		*fout << endl;
	}

	for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			ADDRINT insaddr = INS_Address(ins);
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
			*fout << "NAME:" << imgname << " [" << toHex(saddr) << ',' << toHex(eaddr) << ']' << endl;
			obf_img_saddr = saddr;
			obf_img_eaddr = eaddr;

			// modify tracing start address according to memory loaded address of the executable file
			if (instrc_saddr != 0) instrc_saddr += obf_img_saddr;
			if (instrc_eaddr != 0) instrc_eaddr += obf_img_saddr;

			SEC sec = IMG_SecHead(img);

			obf_txt_saddr = SEC_Address(sec);
			obf_txt_eaddr = obf_txt_saddr + SEC_Size(sec);
		}
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
		if (IMG_IsMainExecutable(img)) *fout << "SECTION: " << *secinfo << endl;

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

				module_info_m[imgname]->fn_infos.push_back(fninfo);
			}
		}
	}
}

// This routine is executed every time a thread is created.
VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	*fout << "Starting Thread " << threadid << endl;
}

// This routine is executed every time a thread is destroyed.
VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	*fout << "Ending Thread " << threadid << endl;
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

	string outputFileName = KnobOutputFile.Value();
	fout = new ofstream(outputFileName.c_str());

	isMemTrace = KnobMemoryTrace.Value();
	isInsTrace = KnobInstructionTrace.Value();
	isDumpCode = KnobDumpCode.Value();
	instrc_saddr = AddrintFromString(KnobTraceStartAddr.Value());
	instrc_eaddr = AddrintFromString(KnobTraceEndAddr.Value());
	instrc_detail = KnobTraceDetail.Value();
	if (KnobFindHandlerAddress.Value()) analysis_step = 1;	

	PIN_InitSymbols();

	// Register Analysis routines to be called when a thread begins/ends
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	if (isMemTrace) {
		TRACE_AddInstrumentFunction(EXE_TRC_MemTrace_Inst, 0);
	}
	if (isInsTrace) {
		TRACE_AddInstrumentFunction(EXE_TRC_InsTrc_Inst, 0);		
	}
	if (instrc_saddr != 0) {
		TRACE_AddInstrumentFunction(EXE_Trc_ins, 0);
	}

	IMG_AddInstrumentFunction(EXE_IMG_inst, 0);

	// SetAddress0x(false);

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
