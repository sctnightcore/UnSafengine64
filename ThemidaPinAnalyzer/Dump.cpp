#include <iostream>
#include <fstream>
#include <set>
#include <map>
#include <string>

#include "pin.H"
#include "dump.h"
#include "ThemidaPinAnalyzer.h"

using namespace std;
namespace WIN {
#include <windows.h>
}
std::vector<IAT_INFO> iat_info;

void DumpData(const char* fname, ADDRINT start, UINT32 size)
{
	ofstream file1(fname, ios::out | ios::binary);
	file1.write((const char*)start, size);
	file1.close();

}

typedef void* (__stdcall* f_CheckSumMappedFile)(void*, WIN::DWORD, WIN::DWORD*, WIN::DWORD*);
#undef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE (WIN::HANDLE)(-1)

#define  dmsg(m, x)  \
      *out << m <<  hexstr((UINT32)(x-vloc+0x6a00)) << endl

ADDRINT Align(ADDRINT dwValue, ADDRINT dwAlign)
{
	if (dwAlign) {
		if (dwValue % dwAlign) {
			return (dwValue + dwAlign) - (dwValue % dwAlign);
		}
	}
	return dwValue;
}

void put_qword(ADDRINT addr, UINT64 val)
{
	UINT64* p = (UINT64*)addr;
	*p = val;
}
void put_dword(ADDRINT addr, UINT32 val)
{
	UINT32* p = (UINT32*)addr;
	*p = val;
}
void put_word(ADDRINT addr, UINT16 val)
{
	UINT16* p = (UINT16*)addr;
	*p = val;

}

void put_xword(ADDRINT addr, ADDRINT val) {
	ADDRINT *p = (ADDRINT*)addr;
	*p = val;
}

void put_many_bytes(ADDRINT dst, ADDRINT src, int len)
{
	UINT8* psrc = (UINT8*)src;
	UINT8* pdst = (UINT8*)dst;
	for (int i = 0; i < len; i++) {
		*pdst++ = *psrc++;
	}
}

UINT64 get_qword(ADDRINT addr, ADDRINT* paddr)
{
	UINT64* p = (UINT64*)addr;
	if (paddr)* paddr += 8;
	return *p;
}
UINT32 get_dword(ADDRINT addr, ADDRINT* paddr)
{
	UINT32* p = (UINT32*)addr;
	if (paddr)* paddr += 4;
	return *p;

}
UINT16 get_word(ADDRINT addr, ADDRINT* paddr)
{
	UINT16* p = (UINT16*)addr;
	if (paddr)* paddr += 2;

	return *p;;

}
void get_many_bytes(ADDRINT dst, ADDRINT src, int len)
{
	UINT8* psrc = (UINT8*)src;
	UINT8* pdst = (UINT8*)dst;
	for (int i = 0; i < len; i++) {
		*pdst++ = *psrc++;
	}
}

void UpdateCheckSumFile(const char* dfile)
{
	WIN::IMAGE_NT_HEADERS* nt;
	WIN::DWORD HeaderSum, CheckSum;
	WIN::HANDLE hFile = INVALID_HANDLE_VALUE;
	WIN::HANDLE hFileMapping = NULL;
	WIN::PVOID BaseAddress = NULL;
	WIN::DWORD FileLen = 0;

	hFile = WIN::CreateFileA(dfile, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (INVALID_HANDLE_VALUE == hFile ||
		NULL == hFile) {
		*fout << "??? File Createion failed: " << dfile << endl;
		return;
	}

	hFileMapping = WIN::CreateFileMapping(hFile, NULL,
		PAGE_READWRITE, 0, 0, NULL);
	if (NULL == hFileMapping)
	{
		*fout << "??? CreateFileMapping failed" << endl;
		WIN::CloseHandle(hFile);
		return;
	}

	BaseAddress = WIN::MapViewOfFile(hFileMapping,
		FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (NULL == BaseAddress)
	{
		*fout << "??? MapViewOfFile Failed" << endl;
		WIN::CloseHandle(hFileMapping);
		WIN::CloseHandle(hFile);
		return;
	}

	WIN::LARGE_INTEGER liSize = { 0, 0 };
	if (TRUE == WIN::GetFileSizeEx(hFile, &liSize))
	{
		FileLen = liSize.LowPart;
	}

	WIN::HMODULE h = WIN::LoadLibraryA("imagehlp.dll");
	if (h) {

		f_CheckSumMappedFile CheckSumMappedFile = (f_CheckSumMappedFile)GetProcAddress(h, "CheckSumMappedFile");
		if (CheckSumMappedFile == NULL) {
			*fout << "??? GetProcAddress CheckSumMappedFile failed" << endl;
			FreeLibrary(h);
			return;
		}
		nt = (WIN::IMAGE_NT_HEADERS*)CheckSumMappedFile(BaseAddress, FileLen, &HeaderSum, &CheckSum);
		if (nt) {

			nt->OptionalHeader.CheckSum = CheckSum;
		}
		else {
			//
			*fout << "??? UpdateChecksum: CheckSUmMappedFIle error " << WIN::GetLastError() << endl;
		}

		FreeLibrary(h);

	}

	WIN::UnmapViewOfFile((WIN::LPCVOID)BaseAddress);
	WIN::CloseHandle(hFileMapping);
	WIN::CloseHandle(hFile);

}
