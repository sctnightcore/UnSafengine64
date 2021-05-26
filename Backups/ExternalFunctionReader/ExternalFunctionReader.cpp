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

namespace NW {
#include <Windows.h>
}



bool read_exports(ADDRINT saddr, vector<ADDRINT> &v_fn_addr, vector<string> &v_fn_name) {
	NW::PIMAGE_DOS_HEADER dos0 = (NW::PIMAGE_DOS_HEADER)saddr;
	NW::PIMAGE_NT_HEADERS nt0 = (NW::PIMAGE_NT_HEADERS)(saddr + dos0->e_lfanew);


	ADDRINT img_size = nt0->OptionalHeader.SizeOfImage;
	ADDRINT edir_va = nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	ADDRINT edir_size = nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	edir_va += saddr;	// RVA to VA
	*fout << "edir:" << toHex(edir_va) << endl;
	*fout << "edir size:" << toHex(edir_size) << endl;

	if (edir_size == 0) return false;

	NW::PIMAGE_EXPORT_DIRECTORY edir = (NW::PIMAGE_EXPORT_DIRECTORY)edir_va;
	ADDRINT addr_names = edir->AddressOfNames + saddr;

	*fout << "addr_names:" << toHex(addr_names) << endl;
	// fout->flush();

	ADDRINT addr_functions = edir->AddressOfFunctions + saddr;
	*fout << "addr_functions:" << toHex(addr_functions) << endl;
	// fout->flush();

	size_t num_functions = edir->NumberOfFunctions;
	*fout << "num_functions:" << toHex(num_functions) << endl;
	// fout->flush();

	size_t num_names = edir->NumberOfNames;
	*fout << "num_names:" << toHex(num_names) << endl;
	// fout->flush();	

	for (size_t i = 0; i < num_functions; i++) {
		ADDRINT* pfn_addr = (ADDRINT*)(addr_functions + i * ADDRSIZE);
		ADDRINT fn_addr = *pfn_addr;
		if (fn_addr > img_size) {
			*fout << "fn_addr is beyond the image size" << endl;
			return false;
		}
		fn_addr += saddr;
		*fout << i << " pfn_addr" << toHex(fn_addr) << endl;
		v_fn_addr.push_back(fn_addr);		
		
		fout->flush();
	}

	for (size_t i = 0; i < num_names; i++) {
		ADDRINT* pnm_addr = (ADDRINT*)(addr_names + i * ADDRSIZE);
		if (*pnm_addr > img_size) {
			*fout << "nm_addr is beyond the image size" << endl;
			return false;
		}
		char* nm_addr = (char*)(*pnm_addr + saddr);
		string fn_name = string(nm_addr);
		if (fn_name.size() > 64) {
			*fout << "function name is not correct\n";
			return false;
		}
		v_fn_name.push_back(fn_name);		
		*fout << i << " fn_name" << fn_name << endl;
		fout->flush();
	}
	return true;
}


