
/* safengine 2.3.9 sample instruction and basic block count
===============================================
MyPinTool analysis results:
Number of threads: 10
Number of instructions of thread 0: 1171795294535586505
Number of instructions of thread 1: 199360176582988
Number of instructions of thread 2: 175701007458700
Number of instructions of thread 3: 68021048744636
Number of instructions of thread 4: 71153435630312236
Number of instructions of thread 5: 13055803832246591
Number of instructions of thread 6: 952954016897874
Number of instructions of thread 7: 848601369067319
Number of instructions of thread 8: 18378013229082
Number of instructions of thread 9: 5073724076898
Number of basic blocks: 0: 622427550
Number of basic blocks: 1: 858932
Number of basic blocks: 2: 468641
Number of basic blocks: 3: 276961
Number of basic blocks: 4: 39127124
Number of basic blocks: 5: 6440398
Number of basic blocks: 6: 529219
Number of basic blocks: 7: 446295
Number of basic blocks: 8: 13796
Number of basic blocks: 9: 5831
===============================================
*/

#include "pin.H"
#include <iostream>
#include <fstream>
#include <vector>
#include <map>

#include "pin_helper.h"

constexpr auto ENABLE_TRACE = 1;

using std::cerr;
using std::string;
using std::endl;

using std::vector;
using std::map;


// Trace information in memory
struct BasicBlockExecution {
    size_t id;  // execution number of thread 0 starting from 1
    ADDRINT addr;   // address of execution
};

map<THREADID, vector<BasicBlockExecution>*> *execution_trace_by_thread;
size_t execution_number_thread0;

// Image & Section Information
ADDRINT main_image_start_address = 0;	
ADDRINT main_image_end_address = 0; 
ADDRINT main_text_section_start_address = 0;	
ADDRINT main_text_section_end_address = 0;

template<typename T>
constexpr auto IS_MAIN_IMG(T address) { return (address >= main_image_start_address && address < main_image_end_address); }

template<typename T>
constexpr auto IS_TEXT_SEC(T address) { return(address >= main_text_section_start_address && address < main_text_section_end_address); }

UINT64 instruction_count[30] = {0};        //number of dynamically executed instructions
UINT64 basic_block_count[30];        //number of dynamically executed basic blocks
UINT64 thread_count = 0;     //total number of threads, including main thread

std::ostream * out = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for MyPinTool output");


/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * Increase counter of the executed basic blocks and instructions.
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
VOID LogBbl(THREADID tid, ADDRINT addr, UINT32 numInstInBbl)
{
    if (ENABLE_TRACE) {
        if (tid == 0) execution_number_thread0++;
        (*execution_trace_by_thread)[tid]->push_back({ execution_number_thread0, addr });
    }

    if (!IS_MAIN_IMG(addr) && GetModuleInfo(addr) != NULL) return;
    
    basic_block_count[tid]++;
    instruction_count[tid] += numInstInBbl;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
 * Insert call to the CountBbl() analysis routine before every basic block 
 * of the trace.
 * This function is called every time a new trace is encountered.
 * @param[in]   trace    trace to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */
VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to CountBbl() before every basic bloc, passing the number of instructions
        BBL_InsertCall(bbl, IPOINT_BEFORE, 
            (AFUNPTR)LogBbl, 
            IARG_THREAD_ID, 
            IARG_INST_PTR, 
            IARG_END);
    }
}

void IMG_Load(IMG img, void* v)
{
	string imgname = IMG_Name(img);
	size_t pos = imgname.rfind("\\") + 1;
	imgname = imgname.substr(pos);
	TO_LOWER(imgname);
	ModuleInfo* modinfo = NULL;
	if (GetModuleInfo(imgname)) return;

	// Record symbol information of a loaded image 
	ADDRINT saddr = IMG_LowAddress(img);
	ADDRINT eaddr = IMG_HighAddress(img);
	modinfo = new ModuleInfo(imgname, saddr, eaddr);

	// EXE analysis
	if (IMG_IsMainExecutable(img))
	{
		main_image_start_address = saddr;
		main_image_end_address = eaddr;
		SEC sec = IMG_SecHead(img);
		main_text_section_start_address = SEC_Address(sec);
		main_text_section_end_address = main_text_section_start_address + SEC_Size(sec);
	}

	// collect symbol information	
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		string secname = SEC_Name(sec);
		ADDRINT saddr = SEC_Address(sec);
		ADDRINT eaddr = saddr + SEC_Size(sec);
		SectionInfo* secinfo = new SectionInfo(imgname, secname, saddr, eaddr);
		modinfo->sec_infos.push_back(secinfo);
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
			string rtnname = RTN_Name(rtn);
			ADDRINT saddr = RTN_Address(rtn);
			ADDRINT eaddr = saddr + RTN_Range(rtn);
			FunctionInfo* fninfo = new FunctionInfo(imgname, rtnname, saddr, eaddr);
		}
	}
}


/*!
 * Increase counter of threads in the application.
 * This function is called for every thread created by the application when it is
 * about to start running (including the root thread).
 * @param[in]   threadIndex     ID assigned by PIN to the new thread
 * @param[in]   ctxt            initial register state for the new thread
 * @param[in]   flags           thread creation flags (OS specific)
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddThreadStartFunction function call
 */
VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    thread_count++;    
    if ((*execution_trace_by_thread)[threadIndex] == NULL) {
        auto t1 = new vector<BasicBlockExecution>;
        t1->reserve(100000000);
        (*execution_trace_by_thread)[threadIndex] = t1;
    }
    
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
    *out <<  "===============================================" << endl;
    *out <<  "Safengine analyzer analysis results: " << endl;
    *out << "Number of threads: " << thread_count << endl;
    for (auto i = 0; i < 25; i++) {
        if (instruction_count[i] == 0) continue;
        *out << "Number of instructions of thread " << i << ": " << instruction_count[i] << endl;
    }    
    for (auto i = 0; i < 25; i++) {
        if (basic_block_count[i] == 0) continue;
        *out << "Number of basic blocks: " << i << ": " << basic_block_count[i] << endl;
    }
    *out <<  "===============================================" << endl;

    ModuleInfo* prev_mod = NULL;
    ModuleInfo* curr_mod = NULL;
    ADDRINT prev_addr = 0;    

    if (!ENABLE_TRACE) return;

    for (const auto& [tid, et] : *execution_trace_by_thread) {
        if (et->size() == 0) continue;
        *out << "THREAD " << tid << " start " << endl;
        for (const auto& [eid, addr] : *et) {
            // log main image execution            
            curr_mod = GetModuleInfo(addr);            
            if (IS_MAIN_IMG(addr) || curr_mod == NULL) {
                *out << eid << ' ' << toHex(addr) << endl;
            }
            else {
                // log API call                               
                if (IS_MAIN_IMG(prev_addr) || prev_mod == NULL) {                
                    if (curr_mod) {
                        auto fn = GetFunctionInfo(curr_mod, addr);
                        if (fn) {
                            *out << eid << ' ' << toHex(addr) << ' ' << curr_mod->name << '.' << fn->name << endl;
                        }
                        else {
                            *out << eid << ' ' << toHex(addr) << ' ' << curr_mod->name << endl;
                        }
                    }                
                    else {
                        *out << tid << ' ' << eid << ' ' << toHex(addr) << " heap" << endl;
                    }
                }
            }
            prev_addr = addr;
            prev_mod = curr_mod;            
        }
        *out << "THREAD " << tid << " end" << endl;
    }
    
}

int main(int argc, char *argv[])
{
    if( PIN_Init(argc,argv) )
    {
        return 0;
    }
    
    execution_trace_by_thread = new map<THREADID, vector<BasicBlockExecution>*>;
    
    // thread 0 records main thread
    // main thread has more than 1 trillion instructions in safengine
    auto t0 = new vector<BasicBlockExecution>;
    t0->reserve(1000000000);
    (*execution_trace_by_thread)[0] = t0;    

    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) { out = new std::ofstream(fileName.c_str());}
    
    PIN_InitSymbols();
    // Register function to be called to instrument traces
    TRACE_AddInstrumentFunction(Trace, 0);

	IMG_AddInstrumentFunction(IMG_Load, 0);

    // Register function to be called for every thread before it starts running
    PIN_AddThreadStartFunction(ThreadStart, 0);

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by PinTracer" << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr <<  "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
