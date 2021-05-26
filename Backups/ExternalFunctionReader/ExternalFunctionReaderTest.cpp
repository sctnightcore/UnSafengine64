// Pin Tracer (for Obfuscated Binary)
// Author: seogu.choi@gmail.com
// Date: 2015.4.25. ~ 

using namespace std;

#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include "ExternalFunctionReader.h"


// obfuscated DLL name
string obf_dll_name = "";

// is dll or exe
bool isDLLAnalysis = false;

ADDRINT main_img_saddr;
ADDRINT main_img_eaddr;

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
	if (isDLLAnalysis && (imgname == obf_dll_name) || !isDLLAnalysis && IMG_IsMainExecutable(img))
	{
		main_img_saddr = saddr;
		main_img_eaddr = eaddr;

		*fout << isDLLAnalysis << endl;
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
			*fout << imgname << ": " << toHex(main_img_saddr) << ' ' << toHex(main_img_eaddr) << endl;
			vector<ADDRINT> v_fn_addr;
			vector<string> v_fn_name;
			read_exports(saddr, v_fn_addr, v_fn_name);
			for (auto addr : v_fn_addr) {
				*fout << toHex(addr) << endl;
			}
			for (auto name : v_fn_name) {
				*fout << name << endl;
			}
		}
	}

}



// This routine is executed every time a thread is created.
VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
	*fout << "# Starting Thread " << threadid << endl;
	ADDRINT addr = PIN_GetContextReg(ctxt, REG_INST_PTR);
	if (addr >= main_img_saddr && addr < main_img_eaddr) {
		*fout << " and exit immediately" << endl;
		((ofstream*)fout)->close();
		PIN_ExitProcess(-1);
	}
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
	if (obf_dll_name != "") isDLLAnalysis = true;

	SetAddress0x(false);

	PIN_InitSymbols();

	PIN_AddThreadStartFunction(ThreadStart, 0);

	// Register Analysis routines to be called when a thread begins/ends
	IMG_AddInstrumentFunction(IMG_Instrument, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
