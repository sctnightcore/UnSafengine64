// Test (for VectoredException)
// Author: seogu.choi@gmail.com
// Date: 2020.3.10. 

#include "Test.h"
namespace NW {
#include <Windows.h>
}
#include <ctime>
#include <iostream>
using namespace std;
extern "C" {
#include "xed-interface.h"
}

string get_timestamp()
{
	stringstream ss;
	ss << time(nullptr);
	return ss.str();
}

//addVectoredExceptionHandler constants:
//CALL_FIRST means call this exception handler first;
//CALL_LAST means call this exception handler last
#define CALL_FIRST 1  
#define CALL_LAST 0


size_t check_disasm(ADDRINT addr)
{
	static bool xed_ok, ok;
	static const unsigned int max_inst_len = 15;
	static xed_error_enum_t xed_code;
	static xed_decoded_inst_t xedd;
	static char buf[2048];
#if defined(TARGET_IA32E)
	static const xed_state_t dstate = { XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b };
#else
	static const xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b };
#endif

	size_t num_check_pass = 0;
	ADDRINT check_start_addr, check_addr;

	xed_decoded_inst_zero_set_mode(&xedd, &dstate);
	xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		return 0;
	}

	// check start	
	for (ADDRINT check_start_addr = addr - 50; check_start_addr < addr - 40; check_start_addr++) {
		check_addr = check_start_addr;
		while (check_addr < addr) {
			xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(check_addr), max_inst_len);
			if (xed_code != XED_ERROR_NONE) {
				break;
			}
			check_addr += xed_decoded_inst_get_length(&xedd);
			if (check_addr == addr) {
				num_check_pass++;
			}
		}
	}
	
	return num_check_pass > 0;
}


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
		if ((exceptionCode >= 0xc0000000) && (exceptionCode <= 0xcfffffff))
		{
			*fout << "Start handling exception. Exception code = " << hex << exceptionCode << endl;			
			fout->flush();
		}
	}
}


void TRC_Instrument(TRACE trc, void *v) 
{
	ADDRINT trc_addr = TRACE_Address(trc);	
	
	if (fnname_m.find(trc_addr) != fnname_m.end()) {
		TRACE_InsertCall(trc, IPOINT_BEFORE, (AFUNPTR)API_Print,
			IARG_CONTEXT,
			IARG_INST_PTR,
			IARG_THREAD_ID,
			IARG_END);
		return;
	}
	
	if (IS_MAIN_IMG(trc_addr)) {
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			ADDRINT bbl_addr = BBL_Address(bbl);
			BBL_InsertCall(
				bbl, IPOINT_BEFORE, (AFUNPTR)INS_Print,
				IARG_CONTEXT,
				IARG_INST_PTR,
				IARG_THREAD_ID,
				IARG_END);
			for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
				asmcode_m[bbl_addr] += toHex(INS_Address(ins)) + ' ' + INS_Disassemble(ins) + '\n';				
			}
		}
	}
}

void INS_Print(CONTEXT* ctxt, ADDRINT addr, THREADID tid)
{	
	PIN_GetLock(&lock, tid + 1);		
	*fout << tid << ' ' << asmcode_m[addr] << endl;
	PIN_ReleaseLock(&lock);
}

void API_Print(CONTEXT* ctxt, ADDRINT addr, THREADID tid)
{
	// print api name and 4 values of the stack 
	ADDRINT rsp = PIN_GetContextReg(ctxt, REG_STACK_PTR);
	PIN_SafeCopy(buf, (VOID*)rsp, ADDRSIZE * 5);
	UINT8* parg1, * parg2, * parg3, * parg4;
	parg1 = buf + ADDRSIZE;
	parg2 = buf + ADDRSIZE * 2;
	parg3 = buf + ADDRSIZE * 3;
	parg4 = buf + ADDRSIZE * 4;
	ADDRINT arg1, arg2, arg3, arg4;
	arg1 = TO_ADDRINT(parg1);
	arg2 = TO_ADDRINT(parg2);
	arg3 = TO_ADDRINT(parg3);
	arg4 = TO_ADDRINT(parg4);

	PIN_GetLock(&lock, tid + 1);
	*fout << "tid:" << tid << ' ' << toHex(addr) << ' ' << fnname_m[addr] << toHex(arg1) << ' ' << toHex(arg2) << ' ' << toHex(arg3) << ' ' << toHex(arg4) << endl;
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
	
	// Record symbol information of a loaded image 
	ADDRINT saddr = IMG_LowAddress(img);
	ADDRINT eaddr = IMG_HighAddress(img);	
	*fout << "NAME:" << imgname << ' ' << toHex(saddr) << ' ' << toHex(eaddr) << endl;


	// EXE analysis
	if (IMG_IsMainExecutable(img))
	{
		main_img_saddr = saddr;
		main_img_eaddr = eaddr;

		SEC sec = IMG_SecHead(img);
		main_txt_saddr = SEC_Address(sec);
		main_txt_eaddr = main_txt_saddr + SEC_Size(sec);
	}
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		string secname = SEC_Name(sec);
		ADDRINT saddr = SEC_Address(sec);
		ADDRINT eaddr = saddr + SEC_Size(sec);
		*fout << "SECTION:" << secname << ' ' << toHex(saddr) << ' ' << toHex(eaddr) << endl;
		if (SEC_Name(sec) == ".text")
		{
			if (IS_MAIN_IMG(saddr))
			{
				main_txt_saddr = SEC_Address(sec);
				main_txt_eaddr = main_txt_saddr + SEC_Size(sec);
			}

			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
			{			
				fnname_m[RTN_Address(rtn)] = RTN_Name(rtn);
			}
		} 
	}
}

// This routine is executed every time a thread is created.
VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
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

	string dot_outputFileName;
	string outputFileName;
	
	outputFileName = string(argv[argc - 1]);
	for (int i = 5; i < argc - 1; i++) {
		string arg = string(argv[i]);		
		if (arg == "--") break;
		outputFileName += '_' + arg;
	}
	outputFileName += get_timestamp() + ".txt";	
	LOG(outputFileName);
	LOG("test" + decstr(1));

	fout = new ofstream(outputFileName.c_str());

	SetAddress0x(false);

	PIN_InitSymbols();

	// Register Analysis routines to be called when a thread begins/ends
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);
	TRACE_AddInstrumentFunction(TRC_Instrument, 0);
	IMG_AddInstrumentFunction(IMG_Instrument, 0);

	PIN_AddContextChangeFunction(OnException, 0);

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
