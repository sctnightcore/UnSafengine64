#include "pin.H"
#include <iostream>
#include <fstream>
#include <vector>
#include <map>

#include "pin_helper.h"

namespace WIN {
#include <Windows.h>
}

using std::cerr;
using std::string;
using std::endl;
using std::vector;
using std::map;
using std::stringstream;


// output
std::ostream* fout = &cerr;
std::stringstream* sout = new stringstream();


/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobLogFile(KNOB_MODE_WRITEONCE, "pintool", "log", "", "specify file name for pintool output");
KNOB<string> KnobDumpFile(KNOB_MODE_WRITEONCE, "pintool", "dmp", "", "specify dump file name");
KNOB<BOOL> KnobCount(KNOB_MODE_WRITEONCE, "pintool", "count", "true", "count # instruction, basic blocks per thread");
KNOB<BOOL> KnobTrace(KNOB_MODE_WRITEONCE, "pintool", "trace", "false", "write execution trace");
KNOB<BOOL> KnobDump(KNOB_MODE_WRITEONCE, "pintool", "dump", "false", "deobfuscate API and make the dump file");
KNOB<BOOL> KnobPauseAtOEP(KNOB_MODE_WRITEONCE, "pintool", "pauseatoep", "false", "pause at oep");


// ====================================
// Trace information
// ====================================
struct BasicBlockExecution {
    size_t id;      // execution trace number of thread 0 starting from 1
    ADDRINT addr;   // execution address
};

map<THREADID, vector<BasicBlockExecution>*>* execution_trace_by_thread;
map<THREADID, ADDRINT> thread_start_addr;
size_t execution_number_thread0;

// ====================================
// Image & Section Information
// ====================================
ADDRINT main_image_start_address = 0;
ADDRINT main_image_end_address = 0;
ADDRINT main_text_section_start_address = 0;
ADDRINT main_text_section_end_address = 0;
ADDRINT main_safengine_section_start_address = 0;
ADDRINT main_safengine_section_end_address = 0;
ADDRINT oep = 0;

// =============================
// memory dump data structures
// =============================
struct OFFSET_AND_SIZE {
    ADDRINT offset;
    size_t size;
};

struct IAT_INFO {
    ADDRINT addr;
    ADDRINT func_addr;
    string func_name;
    string dll_name;
};

struct IAT_DLL_INFO {
    string name;
    UINT32 first_func;
    UINT32 nfunc;
};

// =======================
// memory dump variables
// =======================
// map<ADDRINT, IAT_INFO> iat_elem_by_addr;
vector<IAT_DLL_INFO> dll_list;
ADDRINT dump_image_base;
string dump_file_name = "";

// a copy of original pe header when the image is loaded
void* header_at_load;

// Instruction & Basic Block Count
UINT64 instruction_count[30];        //number of dynamically executed instructions per thread
UINT64 basic_block_count[30];        //number of dynamically executed basic blocks per thread
UINT64 thread_count = 0;     //total number of threads, including main thread

// analysis flags
bool is_enable_count = false;
bool is_enable_trace = false;
bool is_enable_rw_trace = true;
bool is_enable_dump = false;
bool is_pause_at_oep = false;

// IAT 
struct IatElement {
    ADDRINT address;
    ADDRINT function_address;
    string dll_name; 
    string fn_name;
};

// Obfuscated call types
enum class ObfuscatedCallType {
    kOTHER,
    kJMP,
    kCALL,
};

struct ObfuscatedCall {
    ADDRINT address;
    ADDRINT obfuscated_target;
    ADDRINT original_target;
    ObfuscatedCallType call_type;
};


// prepare disassmbly
static const xed_state_t dstate = { XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b };
xed_decoded_inst_t xedd;
xed_error_enum_t xed_code;
char ins_buf[256];

// iat reconstruction
ADDRINT iat_start_address, iat_end_address;
vector<IatElement> iat;
map<ADDRINT, ADDRINT> api_address_to_iat_element;

// obfuscated calls
vector<ObfuscatedCall> obfuscated_calls;

// deobfuscation process
enum class RunUntilAPIFunctionStatus {
    kUninitilaized,
    kCheckNextFunction,
    kMoveToCurrentFunctionStartAddress,
    kMoveToCurrentFunctionNextBasicBlock,
    kInternalAPICall,
    kFinalize,
};
RunUntilAPIFunctionStatus run_until_api_function_status;
int current_obfuscated_call_index = -1;
vector<ADDRINT> rua_trace;
ADDRINT stack_pointer_at_obfuscated_call;

// register context save & restore
CONTEXT saved_context;


// =======================
// memory dump functions
// =======================
ADDRINT Align(ADDRINT dwValue, ADDRINT dwAlign);
void SavePEHeader(ADDRINT img_base);
void DumpUnpackedFile();
void* MakeImportSection(UINT32* size, UINT32* idt_size, UINT32 vloc);
void MakeDllList();
void GetImportComponentSize(UINT32* iidsize0, UINT32* iltsize0, UINT32* iinsize0);
bool FindIAT();
void FindObfuscatedCall();
void FixInstructionAtOEP();

ADDRINT Align(ADDRINT value, ADDRINT align)
{
    if (align) {
        if (value % align) {
            return (value + align) - (value % align);
        }
    }
    return value;
}

// make a copy of original pe header when the image is loaded because themida break the headers from memory dump
void SavePEHeader(ADDRINT img_base)
{
    dump_image_base = img_base;
    header_at_load = malloc(4096);
    memcpy(header_at_load, (const void*)img_base, 4096);
}

// dump memory of each section
void DumpUnpackedFile()
{    
    // use original header from loaded pe in order to evade anti-dump
    void* hdr = header_at_load;
    ADDRINT loadBase0 = (ADDRINT)hdr;

    WIN::IMAGE_DOS_HEADER* dos0 = (WIN::IMAGE_DOS_HEADER*)loadBase0;
    WIN::IMAGE_NT_HEADERS* nt0 = (WIN::IMAGE_NT_HEADERS*)(loadBase0 + dos0->e_lfanew);
    WIN::IMAGE_SECTION_HEADER* sect0 = (WIN::IMAGE_SECTION_HEADER*)
        (loadBase0 + dos0->e_lfanew + sizeof(WIN::DWORD) + sizeof(nt0->FileHeader) + nt0->FileHeader.SizeOfOptionalHeader);
    if (dos0->e_magic != 0x5A4D || nt0->Signature != 0x4550) {
        LOG("[Err] Invalid PE signature");
        return;
    }

    // set OEP
    nt0->OptionalHeader.AddressOfEntryPoint = oep - dump_image_base;

    // set SizeOfCode
    // SizeOfCode is set to zero by safengine for anti-dump
    nt0->OptionalHeader.SizeOfCode = Align(iat_start_address, nt0->OptionalHeader.SectionAlignment) - nt0->OptionalHeader.SectionAlignment;

    // set BaseOfCode
    // BaseOfCode is set to zero by safengine for anti-dump
    nt0->OptionalHeader.BaseOfCode = nt0->OptionalHeader.SectionAlignment;

    // add one more section for import
    int nsec = nt0->FileHeader.NumberOfSections;
    nt0->FileHeader.NumberOfSections++;

    // Original Section
    UINT32 floc = 0x1000;
    for (int i = 0; i < nsec; i++) {
        UINT32 vsize = sect0[i].Misc.VirtualSize;
        UINT32 fsize_a = Align(vsize, nt0->OptionalHeader.FileAlignment);
        sect0[i].SizeOfRawData = fsize_a;
        sect0[i].PointerToRawData = floc;
        floc = floc + fsize_a;
    }

    nt0->OptionalHeader.ImageBase = dump_image_base;

    // start of import section
    UINT32 vloc = sect0[nsec - 1].VirtualAddress +
        Align(sect0[nsec - 1].Misc.VirtualSize, nt0->OptionalHeader.SectionAlignment);

    // import section	
    UINT32 vloc_imp = vloc;
    UINT32 idt_size;
    UINT32 vsize_imp;

    void* fdata_imp = MakeImportSection(&vsize_imp, &idt_size, vloc_imp);

    if (!fdata_imp) {
        *fout << "# Failed to make import section\n";
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

    ADDRINT first_iat_element_addr = iat.begin()->address;
    ADDRINT last_iat_element_addr = iat.rbegin()->address;

    nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = (UINT32)(first_iat_element_addr - dump_image_base);
    nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = (UINT32)(last_iat_element_addr - first_iat_element_addr + ADDRSIZE);

    floc = floc + fsize_imp;
    vloc = vloc_imp + Align(vsize_imp, nt0->OptionalHeader.SectionAlignment);

    nt0->OptionalHeader.SizeOfImage = vloc;
    nt0->OptionalHeader.SizeOfHeaders = 0x400;

    FILE* fp = fopen(dump_file_name.c_str(), "wb");;
    if (fp == NULL) {
        *fout << "# Cannot write " << dump_file_name << endl;
        fout->flush();
        return;
    }

    UINT32 off = 0;;
    fwrite((const void*)hdr, 4096, 1, fp);
    
    off += 4096;

    for (int i = 0; i < nsec; i++) {
        UINT32 fsize = sect0[i].SizeOfRawData;
        ADDRINT addr = sect0[i].VirtualAddress + dump_image_base;
        fwrite((const void*)addr, fsize, 1, fp);
        off += fsize;
    }

    fwrite((const void*)fdata_imp, fsize_imp, 1, fp);
    off += fsize_imp;

    free(hdr);
    free(fdata_imp);
    fclose(fp);
}


void* MakeImportSection(UINT32* size, UINT32* idt_size, UINT32 vloc)
{
    UINT32 iidsize;	// _IMAGE_IMPORT_DESCRIPTOR size
    UINT32 iltsize;	// IAT Size
    UINT32 iinsize;	// _IMAGE_IMPORT_BY_NAME size

    MakeDllList();
    GetImportComponentSize(&iidsize, &iltsize, &iinsize);

    UINT32 import_sec_size = Align((iidsize + iltsize + iinsize), 512);
    ADDRINT import_sec_buf = (ADDRINT)malloc(import_sec_size);
    *fout << "# Import section size: " << import_sec_size << endl;

    int ndll = dll_list.size();
    *fout << "# Number of dll modules: " << ndll << endl;

    // Make Import Directory Table
    WIN::IMAGE_IMPORT_DESCRIPTOR* iid = (WIN::IMAGE_IMPORT_DESCRIPTOR*)(import_sec_buf);
    *fout << "# Import Directory Table at " << toHex(iid) << endl;

    ADDRINT ilt0 = import_sec_buf + iidsize;
    ADDRINT ilt = ilt0;

    int i = 0;
    for (auto& e : dll_list) {
        iid[i].OriginalFirstThunk = ilt - import_sec_buf + vloc;
        iid[i].ForwarderChain = 0;
        iid[i].TimeDateStamp = 0;
        iid[i].FirstThunk = e.first_func;
        ilt += ADDRSIZE * (e.nfunc + 1);
        i++;
    }
    memset(&iid[i], 0, sizeof(WIN::IMAGE_IMPORT_DESCRIPTOR));  // last import directory entry

    // Make Import Names & IAT
    ADDRINT iin = ilt0 + iltsize;   // Image Import Name
    iid = (WIN::IMAGE_IMPORT_DESCRIPTOR*)(import_sec_buf); // Image Import Descriptor
    ilt = ilt0;	// IAT

    i = 0;
    string prev_dll_name;         
    for (auto& [iat_elem_addr, func_addr, dll_name, func_name] : iat) {        
        // Zero bytes between DLLs which means all function names are written and dll name should be written
        // If zero bytes are repeated, there are some missed functions				
        if (func_addr == 0) {
            // Write DLL Names in Image Import Names Table		
            if (prev_dll_name.length() > 0) {
                PutQWORD(ilt, 0);
                ilt += ADDRSIZE;
                int len = prev_dll_name.length() + 1;
                PutBytes(iin, (ADDRINT)prev_dll_name.c_str(), len);
                iid[i].Name = iin - import_sec_buf + vloc;
                iin = iin + Align(len, 2);
                i++;
            }
        }

        // Process ordinal function		
        else if (func_name.find("Ordinal_") != string::npos) {
            ADDRINT ilt_val;
            char* stopstr; string temp = func_name.substr(8);
            ilt_val = (ADDRINT)std::strtoul(temp.c_str(), &stopstr, 10);
            ilt_val |= IMAGE_ORDINAL_FLAG;

            PutQWORD(ilt, ilt_val);
            PIN_SafeCopy((void*)iat_elem_addr, (const void*)&ilt_val, ADDRSIZE);
            ilt += ADDRSIZE;

        }

        // Name function
        else {
            ADDRINT ilt_val = iin - import_sec_buf + vloc;
            PutQWORD(ilt, ilt_val);
            PIN_SafeCopy((void*)(iat_elem_addr + dump_image_base), (const void*)&ilt_val, ADDRSIZE);
            ilt += ADDRSIZE;

            PutWORD(iin, 0);
            iin += 2;

            // Some kernel32.dll functions in memory forwards to ntdll functions
            // So revert it to kernel32.dll function name by removing 'Rtl' prefix 
            // in the function name
            if (dll_name == "ntdll.dll" && func_name.substr(0, 3) == "Rtl") {
                func_name = func_name.substr(3);
            }

            // Write name string
            int len1 = func_name.length() + 1;
            PutBytes(iin, (ADDRINT)func_name.c_str(), len1);
            iin += Align(len1, 2);
        }

        prev_dll_name = dll_name;
    }
    
    *size = import_sec_size;
    *idt_size = iidsize;
    return (void*)import_sec_buf;
}

void MakeDllList() {
    IAT_DLL_INFO dll_info;
    *fout << "# DLL List" << endl;    
    bool is_first_fn = true;
    for (auto& [iat_elem_addr, func_addr, dll_name, func_name] : iat) {
        if (func_addr == 0) {
            // If zero address is repeated, 
            // we may have missed some api functions. 
            // The last few entries of IAT is fixed because the text section refers to those locations. 
            // Then we skip zeros before the last entries. 
            // 
            if (is_first_fn) continue;
            dll_list.push_back(dll_info);
            *fout << dll_info.name << " first_func:" << toHex(dll_info.first_func) <<
                " nfunc:" << dll_info.nfunc << endl;
            is_first_fn = true;
            continue;
        }
        if (is_first_fn) {
            dll_info.first_func = iat_elem_addr - dump_image_base;	// RVA
            dll_info.nfunc = 1;
            dll_info.name = dll_name;
            is_first_fn = false;            
            continue;
        }
        dll_info.nfunc++;
    }
}

void GetImportComponentSize(UINT32* iidsize0, UINT32* iltsize0, UINT32* iinsize0)
{
    UINT32 iidsize = 0;	// _IMAGE_IMPORT_DESCRIPTOR size
    UINT32 iltsize = 0;	// IAT Size
    UINT32 iinsize = 0;	// _IMAGE_IMPORT_BY_NAME size

    size_t n_dll = dll_list.size();
    size_t n_fn = iat.size();
    iidsize = (n_dll + 1) * 20;
    iltsize = n_fn * ADDRSIZE;

    // iin dll name size
    for (auto e : dll_list) {
        int len = e.name.size() + 1;	// Consider null termination			
        iinsize += Align(len, 2);
    }

    // iin func name size
    for (auto& [_, func_addr, dll_name, func_name] : iat) {
        // Ordinal functions do not have a name
        if (func_name.find("Ordinal_") == string::npos) {
            int len = func_name.size() + 1;
            iinsize += 2;
            iinsize += Align(len, 2);
        }
    }

    *iidsize0 = iidsize;
    *iltsize0 = iltsize;
    *iinsize0 = iinsize;
}


// Utilities to handle image (exe/dll) files
inline bool IsMainImage(ADDRINT address) {
    return (address >= main_image_start_address && address < main_image_end_address);
}

inline bool IsMainImageTextSection(ADDRINT address) { 
    return(address >= main_text_section_start_address && address < main_text_section_end_address); 
}

inline bool IsMainImageSafengineSection(ADDRINT address) {
    return(address >= main_safengine_section_start_address && address < main_safengine_section_end_address);
}

void FixInstructionAtOEP() {
    *fout << "# Fixing instruction at OEP:" << toHex(oep - 4) << endl;
    fout->flush();
    oep = oep - 4;
    // 000000014000216C | 48:83EC 28 | sub rsp, 28
    uint32_t* poepins = XED_STATIC_CAST(xed_uint32_t*, oep);
    *poepins = 0x28ec8348;    
}

void ResolveObfuscatedCalls() {
    uint16_t opcode;
    for (auto const& [addr, obfuscated_target, original_target, call_type] : obfuscated_calls) {
        if (original_target == 0) {
            continue;
        }
        if (call_type == ObfuscatedCallType::kCALL) {            
            opcode = 0x15ff;
        }
        else if (call_type == ObfuscatedCallType::kJMP) {
            opcode = 0x25ff;
        }
        ADDRINT indirect_target = api_address_to_iat_element[original_target];
        int32_t relative_address = indirect_target - (addr + 6);
        uint16_t *popcode = XED_STATIC_CAST(xed_uint16_t*, addr);
        *popcode = opcode;
        int32_t* preladdr = XED_STATIC_CAST(xed_int32_t*, addr + 2);
        *preladdr = relative_address;
    }
}

void FindObfuscatedCall() {
    ADDRINT ea = main_text_section_start_address;
    ADDRINT next_ea;

    string asm_line;
    xed_int32_t branch_displacement, memory_displacement, ins_length;
    ADDRINT target_address;

    // Search for obfuscated call candidates
    *fout << "# Searching for obfuscated calls" << endl;
    while (ea < iat_start_address) {        
        xed_decoded_inst_zero_set_mode(&xedd, &dstate);
        xed_code = xed_decode(&xedd, XED_STATIC_CAST(const xed_uint8_t*, ea), 15);
        if (xed_code != XED_ERROR_NONE) {
            ea++;
            continue;
        }

        ins_length = xed_decoded_inst_get_length(&xedd);
        next_ea = ea + ins_length;
        xed_uint8_t opcode = xed_decoded_inst_get_byte(&xedd, 0);
        // jmp or call
        if (opcode == 0xe8 || opcode == 0xe9 || opcode == 0xeb) {
            branch_displacement = xed_decoded_inst_get_branch_displacement(&xedd);
            xed_format_context(XED_SYNTAX_INTEL, &xedd, ins_buf, 256, ea, 0, 0);
            if (branch_displacement) {
                target_address = next_ea + branch_displacement;
                if (IsMainImage(target_address) && target_address > main_text_section_end_address) {
                    *fout << toHex(ea) << ' ' << string(ins_buf) << endl;
                    obfuscated_calls.push_back({ea, target_address, 0, ObfuscatedCallType::kOTHER});
                }
            }
        }
        ea++;        
    }
}

bool FindIAT() {
    *fout << "# Searching for IAT in .text section" << endl;
    ADDRINT idx0 = main_text_section_start_address - main_image_start_address + 0x1000;
    ADDRINT ea0 = idx0 + main_image_start_address;
    ADDRINT iat_start_address_candidate;
    ADDRINT iat_end_address_candidate;
    bool is_found = false;
    while (ea0 < main_text_section_end_address) {
        ADDRINT idx1 = idx0, ea1 = ea0;
        iat_start_address_candidate = ea1;
        size_t non_function_count = 0;
        for (; non_function_count < 2; idx1 += ADDRSIZE, ea1 += ADDRSIZE) {
            ADDRINT fn_addr = *XED_STATIC_CAST(const xed_uint64_t*, ea1);
            if (fn_addr == 0) {
                non_function_count++;
                iat.push_back({ ea1, 0, "", "" });
                continue;
            }
            ModuleInformation* mdl = GetModuleInformation(fn_addr);
            if (mdl == NULL) {
                non_function_count++;
                iat.push_back({ ea1, 0, "", "" });
                continue;
            }
            FunctionInformation* fn = GetFunctionInformation(mdl, fn_addr);
            if (fn == NULL || fn->name == ".text") {
                non_function_count++;
                iat.push_back({ ea1, 0, "", "" });
                continue;
            }
            if (IsMainImage(fn_addr)) break;
            iat.push_back({ ea1, fn_addr, mdl->name, fn->name });
            *fout << toHex(ea1) << ' ' << toHex(fn_addr) << ' ' << mdl->name << ' ' << fn->name << endl;
            non_function_count = 0;
        }
        iat_end_address_candidate = ea1;
        if (iat_end_address_candidate - iat_start_address_candidate > ADDRSIZE * 10) {
            is_found = true;
            break;
        }
        idx0 += 0x1000;
        ea0 += 0x1000;
        iat.clear();
    }
    if (is_found) {
        iat_start_address = iat_start_address_candidate;
        iat_end_address = iat_end_address_candidate;
        return true;
    }
    return false;
}

// Create PIN_WAIT directory and wait until the directory is removed by user. 
// this is for manually dumping the executed files using IAT reconstruction tools such as Scylla x64
void PauseAtOEP() {
    NATIVE_FD fd;
    OS_RETURN_CODE hdl = { OS_RETURN_CODE_NO_ERROR, 0 };
    OS_MkDir("PIN_WAIT", OS_FILE_PERMISSION_TYPE_ALL_USER);
    while (hdl.generic_err == OS_RETURN_CODE_NO_ERROR) {
        PIN_Sleep(1000);
        hdl = OS_OpenDirFD("PIN_WAIT", &fd);
        OS_CloseFD(fd);
    }
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

// temporary for logging deobfuscation of one obfuscated API call 'MessageBoxA'
bool is_log_messagebox_deob = false;
size_t cnt_log_messagebox_deob_bbl = 0;
size_t cnt_log_messagebox_deob_ins = 0;

VOID BasicBlockAnalysis(CONTEXT* ctxt, THREADID tid, ADDRINT addr, UINT32 numInstInBbl, UINT32 bblSz)
{

    if (thread_start_addr.find(tid) == thread_start_addr.end()) {
        thread_start_addr[tid] = addr;
        *fout << "Thread " << tid << " Start Address: " << toHex(addr) << endl;
    }

    if (is_enable_trace) {
        if (tid == 0) execution_number_thread0++;
        (*execution_trace_by_thread)[tid]->push_back({ execution_number_thread0, addr });
    }

    
    if (is_enable_count) {
        if (run_until_api_function_status == RunUntilAPIFunctionStatus::kUninitilaized && IsMainImage(addr) || GetModuleInformation(addr) == NULL) {
            basic_block_count[tid]++;
            instruction_count[tid] += numInstInBbl;
        }        
    }

    if (!is_enable_dump && is_pause_at_oep && tid == 0) {
        // pause application until PIN_WAIT directory is deleted
        if (IsMainImageTextSection(addr)) {
            oep = addr;
            *fout << "# OEP: " << toHex(oep) << endl;
            PIN_StopApplicationThreads(tid);
            PauseAtOEP();
        }        
    }

    if (is_enable_dump && tid == 0) {
        if (oep == 0) {
            if (IsMainImageTextSection(addr)) {
                oep = addr;
                *fout << "# OEP: " << toHex(oep) << endl;

                // make a memory dump file by Scylla x64                
                *fout << "# Searching for IAT" << endl;

                bool bRes = FindIAT();
                if (bRes) {

                    *fout << "# IAT address: " << toHex(iat_start_address) << endl;
                    *fout << "# IAT size: " << toHex(iat_end_address - iat_start_address) << endl;
                    for (const auto& [addr, func_addr, dll_name, func_name] : iat) {
                        if (func_addr == 0) continue;
                        api_address_to_iat_element[func_addr] = addr;
                    }

                    FindObfuscatedCall();
                                        
                    *fout << "# Resolving obfuscated API calls" << endl;
                    PIN_SaveContext(ctxt, &saved_context);
                    run_until_api_function_status = RunUntilAPIFunctionStatus::kCheckNextFunction;
                    PIN_StopApplicationThreads(tid);
                }
            }        
        }

        if (is_log_messagebox_deob) {
            cnt_log_messagebox_deob_ins += numInstInBbl;
            cnt_log_messagebox_deob_bbl++;
            string s;
            ADDRINT current_addr = addr;
            size_t sz;
            while (current_addr < addr + bblSz) {
                 sz = get_disasm(current_addr, s);
                *fout << toHex(current_addr) << ' ' << s << endl;
                current_addr += sz;
            }                        
        }

        while (run_until_api_function_status != RunUntilAPIFunctionStatus::kUninitilaized) {            
            if (run_until_api_function_status == RunUntilAPIFunctionStatus::kCheckNextFunction) {
                current_obfuscated_call_index++;
                if (current_obfuscated_call_index >= obfuscated_calls.size()) {
                    run_until_api_function_status = RunUntilAPIFunctionStatus::kFinalize;
                    continue;                    
                }
                ADDRINT obfuscated_call_source = obfuscated_calls[current_obfuscated_call_index].address;
                
                run_until_api_function_status = RunUntilAPIFunctionStatus::kMoveToCurrentFunctionStartAddress;
                PIN_SetContextReg(&saved_context, REG_INST_PTR, obfuscated_call_source);
                PIN_ExecuteAt(&saved_context);
                break;  // cannot reach here
            }

            if (run_until_api_function_status == RunUntilAPIFunctionStatus::kMoveToCurrentFunctionStartAddress) {
                rua_trace.clear();
                rua_trace.push_back(addr);
                stack_pointer_at_obfuscated_call = PIN_GetContextReg(ctxt, REG_STACK_PTR);
                
                if (addr == 0x00000001400010E1) {
                    is_log_messagebox_deob = true;
                    *fout << endl << "Logging deobfuscation of 'call MessageBoxA' started" << endl;
                    *fout << "RSP=" << toHex(PIN_GetContextReg(ctxt, REG_STACK_PTR)) << endl;;
                }

                run_until_api_function_status = RunUntilAPIFunctionStatus::kMoveToCurrentFunctionNextBasicBlock;
                break;
            }

            else if (run_until_api_function_status == RunUntilAPIFunctionStatus::kMoveToCurrentFunctionNextBasicBlock) {
                rua_trace.push_back(addr);
                if (!IsMainImage(addr)) {                    
                    FunctionInformation* fn = GetFunctionInformation(addr);
                    if (fn) {
                        // GetModuleHandleA is called during API resolving
                        if (fn->name == "GetModuleHandleA") {
                            run_until_api_function_status = RunUntilAPIFunctionStatus::kInternalAPICall;
                            continue;
                        }
                        ADDRINT stack_pointer_at_api = PIN_GetContextReg(ctxt, REG_STACK_PTR);
                        string call_mnemonic = "";
                        if (stack_pointer_at_obfuscated_call == stack_pointer_at_api) {
                            obfuscated_calls[current_obfuscated_call_index].call_type = ObfuscatedCallType::kJMP;
                            call_mnemonic = "jmp";
                        }
                        else if (stack_pointer_at_obfuscated_call - stack_pointer_at_api == ADDRSIZE) {
                            obfuscated_calls[current_obfuscated_call_index].call_type = ObfuscatedCallType::kCALL;
                            call_mnemonic = "call";
                        }                        

                        if (obfuscated_calls[current_obfuscated_call_index].call_type != ObfuscatedCallType::kOTHER) {

                            *fout << toHex(obfuscated_calls[current_obfuscated_call_index].address) << ' ';
                            *fout << call_mnemonic << ' ' << fn->module_name << ':' << fn->name << endl;
                            obfuscated_calls[current_obfuscated_call_index].original_target = addr;
                        }
                        
                    }   

                    if (is_log_messagebox_deob) {
                        is_log_messagebox_deob = false;

                        *fout << "RSP=" << toHex(PIN_GetContextReg(ctxt, REG_STACK_PTR)) << endl;
                        *fout << "Number of instructions while deobfuscating MessageBoxA: " << cnt_log_messagebox_deob_ins << endl;
                        *fout << "Number of basic blocks while deobfuscating MessageBoxA: " << cnt_log_messagebox_deob_bbl << endl;
                        *fout << "Logging deobfuscation of 'call MessageBoxA' ended" << endl << endl;
                    }

                    run_until_api_function_status = RunUntilAPIFunctionStatus::kCheckNextFunction;
                    continue;
                }

                if (!IsMainImageSafengineSection(addr)) {
                    run_until_api_function_status = RunUntilAPIFunctionStatus::kCheckNextFunction;
                    continue;
                }
                break;
            }
             
            else if (run_until_api_function_status == RunUntilAPIFunctionStatus::kInternalAPICall) {
                if (IsMainImageSafengineSection(addr)) {
                    run_until_api_function_status = RunUntilAPIFunctionStatus::kMoveToCurrentFunctionNextBasicBlock;
                    continue;

                }
                if (!IsMainImage(addr)) {
                    FunctionInformation* fn = GetFunctionInformationWithStartAddress(addr);
                    if (fn) {
                        rua_trace.push_back(addr);                        
                    }                    
                }
                break;
            }

            else if (run_until_api_function_status == RunUntilAPIFunctionStatus::kFinalize) {
                ResolveObfuscatedCalls();
                FixInstructionAtOEP();                
                DumpUnpackedFile();
                fout->flush();

                // pause application until PIN_WAIT directory is deleted
                if (is_pause_at_oep) {
                    PauseAtOEP();
                }
                
                PIN_ExitApplication(0);
            }

            break;  // cannot reach here
        }
        
    }
}

VOID MemReadAnalysis(THREADID tid, ADDRINT ins_addr, ADDRINT mem_addr, UINT32 mem_sz) {     
    if (mem_addr >= 0x1401a0000 && mem_addr < main_image_end_address) {

    }
    else {
        return;
    }

    switch (mem_sz) {
    case 1:                
        *sout << '[' << tid << "] Rb:" << toHex(mem_addr) << ' ' << toHex1(GetBYTE(mem_addr)) << endl;
        break;
    case 2:
        *sout << '[' << tid << "] Rw:" << toHex(mem_addr) << ' ' << toHex2(GetWORD(mem_addr)) << endl;
        break;
    case 4:
        *sout << '[' << tid << "] Rd:" << toHex(mem_addr) << ' ' << toHex4(GetDWORD(mem_addr)) << endl;
        break;
    case 8:
        *sout << '[' << tid << "] Rd:" << toHex(mem_addr) << ' ' << toHex8(GetQWORD(mem_addr)) << endl;
        break;
    }        
}

VOID MemWriteAnalysis(THREADID tid, ADDRINT ins_addr, ADDRINT mem_addr, UINT32 mem_sz) {    
    if (mem_addr >= 0x1401a0000 && mem_addr < main_image_end_address) {

    }
    else {
        return;
    }

    switch (mem_sz) {
    case 1:
        *sout << '[' << tid << "] Wb:" << toHex(mem_addr) << ' ' << toHex1(GetBYTE(mem_addr)) << endl;
        break;
    case 2:
        *sout << '[' << tid << "] Ww:" << toHex(mem_addr) << ' ' << toHex2(GetWORD(mem_addr)) << endl;
        break;
    case 4:
        *sout << '[' << tid << "] Wd:" << toHex(mem_addr) << ' ' << toHex4(GetDWORD(mem_addr)) << endl;
        break;
    case 8:
        *sout << '[' << tid << "] Wd:" << toHex(mem_addr) << ' ' << toHex8(GetQWORD(mem_addr)) << endl;
        break;
    }
}


/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        BBL_InsertCall(bbl, IPOINT_BEFORE, 
            (AFUNPTR)BasicBlockAnalysis, 
            IARG_CONTEXT,
            IARG_THREAD_ID, 
            IARG_INST_PTR, 
            IARG_UINT32, BBL_NumIns(bbl), 
            IARG_UINT32, BBL_Size(bbl),
            IARG_END);
        
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            UINT32 memOperands = INS_MemoryOperandCount(ins);
            for (UINT32 memOp = 0; memOp < memOperands; memOp++)
            {
                if (INS_MemoryOperandIsRead(ins, memOp)) {
                    INS_InsertPredicatedCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)MemReadAnalysis,
                        IARG_THREAD_ID, 
                        IARG_INST_PTR,
                        IARG_MEMORYOP_EA, memOp,
                        IARG_MEMORYREAD_SIZE,
                        IARG_END);
                }
                if (INS_MemoryOperandIsWritten(ins, memOp) && 
                    INS_IsValidForIpointAfter(ins))
                {
                    INS_InsertPredicatedCall(
                        ins, IPOINT_AFTER, (AFUNPTR)MemWriteAnalysis,
                        IARG_THREAD_ID, 
                        IARG_INST_PTR,
                        IARG_MEMORYOP_EA, memOp,
                        IARG_MEMORYWRITE_SIZE,
                        IARG_END);
                }
            }
        }

    }
}

void IMG_Load(IMG img, void* v)
{
	string imgname = IMG_Name(img);
	size_t pos = imgname.rfind("\\") + 1;
	imgname = imgname.substr(pos);
    TO_LOWER(imgname);
    ADDRINT saddr = IMG_LowAddress(img);
    ADDRINT eaddr = IMG_HighAddress(img);
	
    *fout << "IMAGE:" << imgname << " Loaded " << toHex(saddr) << '-' << toHex(eaddr) << endl;
	ModuleInformation* modinfo = NULL;
	if (GetModuleInformation(imgname)) return;

	// Record symbol information of a loaded image 	
	modinfo = new ModuleInformation(imgname, saddr, eaddr);

	if (IMG_IsMainExecutable(img))
	{
		main_image_start_address = saddr;
		main_image_end_address = eaddr;
		SEC sec = IMG_SecHead(img);
		main_text_section_start_address = SEC_Address(sec);
		main_text_section_end_address = main_text_section_start_address + SEC_Size(sec);
        SEC next_sec = SEC_Next(sec);   // .sedata section
        main_safengine_section_start_address = SEC_Address(next_sec);
        main_safengine_section_end_address = main_safengine_section_start_address + SEC_Size(next_sec);      
        SavePEHeader(main_image_start_address);
	}

	// Collect symbol information	
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		string secname = SEC_Name(sec);
		ADDRINT saddr = SEC_Address(sec);
		ADDRINT eaddr = saddr + SEC_Size(sec);
		SectionInformation* secinfo = new SectionInformation(imgname, secname, saddr, eaddr);
		modinfo->sec_infos.push_back(secinfo);
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
			string rtnname = RTN_Name(rtn);
			ADDRINT saddr = RTN_Address(rtn);
			ADDRINT eaddr = saddr + RTN_Range(rtn);
			FunctionInformation* fninfo = new FunctionInformation(imgname, rtnname, saddr, eaddr);
		}
	}
}


VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    thread_count++;    
    if (is_enable_trace) {
        if ((*execution_trace_by_thread)[threadIndex] == NULL) {
            auto t1 = new vector<BasicBlockExecution>;
            t1->reserve(100000000);
            (*execution_trace_by_thread)[threadIndex] = t1;
        }
    }
    
    *fout << "Thread " << threadIndex << " Started" << endl;
}

VOID ThreadFini(THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v) {
    // thread_count--;
    *fout << "Thread " << threadid << " Ended" << endl;
}

VOID Fini(INT32 code, VOID *v)
{
    *fout << "# Program Ended" << endl;
    // write statistics
    if (is_enable_count) {        
        *fout << "# Statistics: " << endl;
        *fout << "# Number of threads: " << thread_count << endl;
        for (auto i = 0; i < 25; i++) {
            if (instruction_count[i] == 0) continue;
            *fout << "# Number of instructions of thread " << i << ": " << instruction_count[i] << endl;
        }
        for (auto i = 0; i < 25; i++) {
            if (basic_block_count[i] == 0) continue;
            *fout << "# Number of basic blocks: " << i << ": " << basic_block_count[i] << endl;
        }
        *fout << endl;
    }
    
    // write rw trace
    if (is_enable_rw_trace) {
        *fout << sout->str();
    }
    
    // write execution trace
    if (is_enable_trace) {
        ModuleInformation* prev_mod = NULL;
        ModuleInformation* curr_mod = NULL;
        ADDRINT prev_addr = 0;
        *fout << "# Execution Trace" << endl;

        for (const auto& [tid, et] : *execution_trace_by_thread) {
            if (et->size() == 0) continue;
            *fout << "# THREAD " << tid << " started " << endl;
            for (const auto& [eid, addr] : *et) {
                // log main image execution            
                curr_mod = GetModuleInformation(addr);
                if (IsMainImage(addr) || curr_mod == NULL) {
                    *fout << eid << ' ' << toHex(addr) << endl;
                }
                else {
                    // log API call                               
                    if (IsMainImage(prev_addr) || prev_mod == NULL) {
                        if (curr_mod) {
                            auto fn = GetFunctionInformation(curr_mod, addr);
                            if (fn) {
                                *fout << eid << ' ' << toHex(addr) << ' ' << curr_mod->name << '.' << fn->name << endl;
                            }
                            else {
                                *fout << eid << ' ' << toHex(addr) << ' ' << curr_mod->name << endl;
                            }
                        }
                        else {
                            *fout << tid << ' ' << eid << ' ' << toHex(addr) << " heap" << endl;
                        }
                    }
                }
                prev_addr = addr;
                prev_mod = curr_mod;
            }
            *fout << "# THREAD " << tid << " ended" << endl;
        }
        *fout << endl;
    }
    if (is_enable_dump) {
        if (run_until_api_function_status != RunUntilAPIFunctionStatus::kFinalize) {
            for (auto addr : rua_trace) {
                *fout << toHex(addr) << endl;
            }
        }        
    }    
}

int main(int argc, char *argv[])
{
    if( PIN_Init(argc,argv) )
    {
        return 0;
    }

    string exe_file_name = string(argv[argc - 1]);
    size_t pos = exe_file_name.rfind('.');
    if (pos != string::npos) {
        exe_file_name = exe_file_name.substr(0, pos);
    }
    
    string output_file_name = KnobLogFile.Value();
    if (output_file_name == "") {
        output_file_name = exe_file_name + ".log";                            
    }

    dump_file_name = KnobDumpFile.Value();
    if (dump_file_name == "") {
        dump_file_name = exe_file_name + "_dmp.exe";
    }

    LOG("Output file name:" + output_file_name);
    LOG("Dump file name:" + dump_file_name);
    is_enable_trace = KnobTrace.Value();
    is_enable_dump = KnobDump.Value();
    is_enable_count = KnobCount.Value();
    is_pause_at_oep = KnobPauseAtOEP.Value();

    if (!output_file_name.empty()) { 
        fout = new std::ofstream(output_file_name.c_str());        
    }
    
    // for execution trace
    if (is_enable_trace) {
        execution_trace_by_thread = new map<THREADID, vector<BasicBlockExecution>*>;

        // thread 0 records main thread
        // main thread has more than 1 trillion instructions in safengine
        auto t0 = new vector<BasicBlockExecution>;
        t0->reserve(1000000000);
        (*execution_trace_by_thread)[0] = t0;
    }
    
    PIN_InitSymbols();    
    TRACE_AddInstrumentFunction(Trace, 0);
	IMG_AddInstrumentFunction(IMG_Load, 0);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    PIN_AddFiniFunction(Fini, 0);   
    PIN_StartProgram();
    
    return 0;
}
