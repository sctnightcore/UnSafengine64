#pragma once

#include "pin.H"
#include "PinSymbolInfoUtil.h"

struct IAT_INFO {
	ADDRINT addr;
	fn_info_t *fn_info;
	IAT_INFO(ADDRINT a, fn_info_t* f) : addr(a), fn_info(f) {}
};


struct REL_INFO {
	UINT32 pageRVA;
	UINT32 blkSize;
	std::vector<UINT16>* reldata;
};

void DumpUnpackedFile();

void UpdateCheckSumFile(const char* dfile);
void put_qword(ADDRINT addr, UINT64 val);
void put_dword(ADDRINT addr, UINT32 val);
void put_word(ADDRINT addr, UINT16 val);
void put_xword(ADDRINT addr, ADDRINT val);
void put_many_bytes(ADDRINT dst, ADDRINT src, int len);

UINT64 get_qword(ADDRINT addr, ADDRINT* paddr);
UINT32 get_dword(ADDRINT addr, ADDRINT* paddr);
UINT16 get_word(ADDRINT addr, ADDRINT* paddr);
void get_many_bytes(ADDRINT dst, ADDRINT src, int len);


ADDRINT Align(ADDRINT dwValue, ADDRINT dwAlign);
void DumpData(const char* fname, ADDRINT start, UINT32 size);
