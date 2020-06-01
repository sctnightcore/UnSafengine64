// Pin Tracer (for Obfuscated Binary)
// Author: seogu.choi@gmail.com
// Date: 2015.4.25. ~ 

using namespace std;

#include "pin.H"
#include "StrUtil.h"
#include <iostream>
#include <fstream>
#include <map>
#include <set>


// standard output & file output 
ostream* fout = &cerr;	// result output

// obfuscated DLL name
string obf_dll_name = "";

// is dll or exe
bool isDLLAnalysis = false;

namespace NW {
#include <Windows.h>
}


KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "result.txt", "specify file name for the result");
KNOB<string> KnobDLLFile(KNOB_MODE_WRITEONCE, "pintool", "dll", "", "specify packed dll file");


// IMG instrumentation function for EXE files
void IMG_Instrument(IMG img, void* v)
{
	// Trim image name
	string imgname = IMG_Name(img);
	size_t pos = imgname.rfind("\\") + 1;
	imgname = imgname.substr(pos);

	// Record symbol information of a loaded image 
	ADDRINT saddr = IMG_LowAddress(img);
	ADDRINT eaddr = IMG_HighAddress(img);

	bool found_export = false;
	if (isDLLAnalysis && imgname == obf_dll_name || IMG_IsMainExecutable(img))
	{
		for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
		{
			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
			{
				string rtnname = RTN_Name(rtn);
				ADDRINT saddr = RTN_Address(rtn);
				ADDRINT eaddr = saddr + RTN_Range(rtn);

				*fout << rtnname << ' ' << toHex(saddr) << ' ' << toHex(eaddr) << endl;

				found_export = true;
			}
		}

		if (!found_export) 
		{

		}

	}


}


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
	
	fout = new ofstream(outputFileName.c_str());
	
	obf_dll_name = KnobDLLFile.Value();

	SetAddress0x(false);

	PIN_InitSymbols();

	// Register Analysis routines to be called when a thread begins/ends
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
