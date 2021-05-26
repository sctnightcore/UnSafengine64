// Find Context Switch in VM
// 2019.11.15.~
// seogu.choi@gmail.com

#include "FindContextSwitch.h"

using namespace std;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "result.txt", "specify file name for the result");
KNOB<string> KnobDLLFile(KNOB_MODE_WRITEONCE, "pintool", "dll", "", "specify packed dll file");
KNOB<string> KnobVMSection(KNOB_MODE_WRITEONCE, "pintool", "vmsection", "3", "specify vm section number");


void BBL_Analysis(CONTEXT *ctx, THREADID tid, ADDRINT saddr, ADDRINT eaddr) {
	auto it = thr_prev_addr.find(tid);
	if (it == thr_prev_addr.end()) {
		thr_prev_addr[tid] = eaddr;
		return;
	}
	ADDRINT prev = thr_prev_addr[tid];
	bool found = false;

	if (IS_VM_SEC(saddr)) {
		if (IS_TEXT_SEC(prev)) {
			// TEXT -> VM
			*fout << "TEXT->VM: " << toHex(prev) << "->" << toHex(saddr) << endl;
			found = true;
		} 
		else if (!IS_MAIN_IMG(prev)) {
			// API -> VM			
			*fout << "API->VM: " << toHex(prev) << ':' << GetAddrInfo(prev) << "->" << toHex(saddr) << endl;
			found = true;
		}
	}	
	else if (IS_VM_SEC(prev)) {
		if (IS_TEXT_SEC(saddr)) {
			// VM -> TEXT
			*fout << "VM->TEXT: " << toHex(prev) << "->" << toHex(saddr) << endl;
			found = true;
		}
		else if (!IS_MAIN_IMG(prev)) {
			// VM -> API
			*fout << "VM->API: " << toHex(saddr) << "->" << toHex(prev) << ':' << GetAddrInfo(prev) << endl;
			found = true;
		}
	}

	if (found) {
		// print stack pointer
		ADDRINT stack_ptr = PIN_GetContextReg(ctx, REG_STACK_PTR);
		*fout << "Stack Pointer:" << toHex(stack_ptr) << endl;
	}

	thr_prev_addr[tid] = eaddr;
}

void TRC_Instrument(TRACE trace, void *v)
{
	ADDRINT addr = TRACE_Address(trace);

	// skip dll module
	mod_info_t *mod_info = GetModuleInfo(addr);


	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {		
		ADDRINT bbl_addr = BBL_Address(bbl);
		size_t bbl_size = BBL_Size(bbl);		

		// log jmp dword ptr [...] instruction
		// log jmp exx instruction
		// log ret instruction in vm section
		BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)BBL_Analysis,
			IARG_CONTEXT,
			IARG_THREAD_ID,
			IARG_INST_PTR,		
			IARG_ADDRINT, INS_Address(BBL_InsTail(bbl)), 
			IARG_END);
		/*INS ins = BBL_InsTail(bbl);
		
		if (INS_IsControlFlow(ins)) {
			
		}	*/	
	}
}

void Pintool_Instrument_IMG(IMG img, void *v)
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

	if (is_dll_analysis)
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

			SEC sec = IMG_SecHead(img);
			main_txt_saddr = SEC_Address(sec);
			main_txt_eaddr = main_txt_saddr + SEC_Size(sec);
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
		else if (IS_MAIN_IMG(saddr) && cnt == vmsec_name)
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
	
	string outputFileName = KnobOutputFile.Value();
	if (outputFileName == "result.txt")
	{
		outputFileName = string(argv[argc - 1]);
		
		bool flag = false;
		for (int i = 3; i < argc - 1; i++) {
			string arg = string(argv[i]);			
			if (arg.at(0) == '-') {
				if (arg.at(1) == '-') break;
				if (arg.at(1) != 't') {
					flag = true;
					outputFileName += '_' + arg;
				}
			}
			else {
				if (flag) {					
					outputFileName += '_' + arg;
				}
				flag = false;
			}						
		}		
		outputFileName += ".txt";	
	}
	LOG(outputFileName);

	
	fout = new ofstream(outputFileName.c_str());
	
	obf_dll_name = KnobDLLFile.Value();	
	vmsec_name = Uint32FromString(KnobVMSection.Value());
	
	PIN_InitSymbols();

	// Register Analysis routines to be called when a thread begins/ends
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);
	TRACE_AddInstrumentFunction(TRC_Instrument, 0);
	IMG_AddInstrumentFunction(Pintool_Instrument_IMG, 0);

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
