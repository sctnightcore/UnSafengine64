/* FixPEChecksum fixes the PE checksum in 32-bit and 64-bit PE files.
Usage: FixPEChecksum [--no-csv-header] [--dryrun] [--] <file> [[file]...]
cl /W4 FixPEChecksum.cpp
Copyright (C) 2018 Jay Satiro <raysatiro@yahoo.com>
All rights reserved. License GPLv3+: GNU GPL version 3 or later
<http://www.gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
https://gist.github.com/jay/d662cc9615f3e1ffc75e4ae9485da685
*/

#define _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <imagehlp.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib, "imagehlp.lib")

// main macro for FAIL macros used by FixPEChecksum()
#define FAIL2(message, show_gle) \
  __pragma(warning(push)) \
  __pragma(warning(disable:4127)) \
  do { \
    DWORD gle = GetLastError(); \
    fwprintf(stderr, L"Error: %S.\n", (message)); \
    if(show_gle) { \
      wchar_t *gle_msg = GetErrorMessage(gle); \
      fwprintf(stderr, L"GetLastError: (%u) %s.\n", \
               gle, (gle_msg ? gle_msg : L"<unknown>")); \
      free(gle_msg); \
    } \
    fwprintf(stderr, L"Filename: \"%s\"\n", filename); \
    return false; \
  } while(0) \
  __pragma(warning(pop))

// Show 'message' and return false
#define FAIL(message) \
  FAIL2((message), FALSE)

// Show GetLastError, show 'message' and return false
#define GLE_FAIL(message) \
  FAIL2((message), TRUE)

// If 'condition' then show 'message' and return false
#define FAIL_IF(condition, message) \
  __pragma(warning(push)) \
  __pragma(warning(disable:4127)) \
  do { if(condition) FAIL((message)); } while(0) \
  __pragma(warning(pop))

// If 'condition' then show GetLastError, show 'message' and return false
#define GLE_FAIL_IF(condition, message) \
  __pragma(warning(push)) \
  __pragma(warning(disable:4127)) \
  do { if(condition) GLE_FAIL((message)); } while(0) \
  __pragma(warning(pop))

enum action {
	ACTION_DRYRUN,   // Test if checksum can be fixed but do not write to file.
	ACTION_FIX       // Fix the checksum and write to file.
};

/*
GetErrorMessage gets the error message from a GetLastError code.
Returns a heap-allocated string, or NULL if no message was found.
*/
wchar_t* GetErrorMessage(DWORD gle)
{
	DWORD x;
	size_t len;
	wchar_t* buffer;
	const size_t bufsize = 1024 * sizeof(wchar_t);

	buffer = (wchar_t*)malloc(bufsize);

	if (!buffer)
		return NULL;

	x = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, NULL, gle,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		buffer, bufsize / sizeof(wchar_t), NULL);

	if (!x) {
		free(buffer);
		return NULL;
	}

	len = wcslen(buffer);

	// replace newlines with spaces
	for (size_t i = 0; i < len; ++i) {
		if (buffer[i] == '\r' || buffer[i] == '\n')
			buffer[i] = ' ';
	}

	// trim trailing spaces
	for (size_t i = len; i-- > 0 && buffer[i] == ' '; ) {
		buffer[i] = 0;
		--len;
	}

	// remove period
	if (len > 1 && buffer[len - 1] == '.') {
		buffer[len - 1] = 0;
		--len;
	}

	if (!len) {
		free(buffer);
		return NULL;
	}

	return buffer;
}

/*
FixPEChecksum fixes the PE checksum in both 32-bit and 64-bit files.
Returns true on success and:
'before' receives the file's checksum before any changes
'after' receives the file's checksum after any changes
On failure an error message is written to stderr and false is returned.
*/
bool FixPEChecksum(const wchar_t* filename, action action,
	DWORD* before, DWORD* after)
{
	__try {
		HANDLE f = INVALID_HANDLE_VALUE;

		__try {
			f = CreateFileW(filename,
				(GENERIC_READ |
				(action != ACTION_DRYRUN ? GENERIC_WRITE : 0)),
				FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);

			GLE_FAIL_IF(f == INVALID_HANDLE_VALUE, "CreateFileW");

			/* If a file is modified via mapped view then Windows may skip updating
			   the file times of last modified. For consistency disable last modified
			   and last accessed updates. This call may fail if the file system
			   doesn't support it. */
			FILETIME invalid_time = { (DWORD)-1, (DWORD)-1 };
			SetFileTime(f, NULL, &invalid_time, &invalid_time);

			LARGE_INTEGER li;

			GLE_FAIL_IF(!GetFileSizeEx(f, &li), "GetFileSizeEx");

			FAIL_IF(li.HighPart, "File size is too large");

			FAIL_IF(!li.LowPart, "File size is 0");

			DWORD fsize = li.LowPart;
			HANDLE fmap = NULL;

			__try {
				fmap = CreateFileMapping(f, NULL,
					(action != ACTION_DRYRUN ?
						PAGE_READWRITE : PAGE_READONLY),
					0, fsize, NULL);

				GLE_FAIL_IF(!fmap, "CreateFileMapping");

				void* fmem = NULL;

				__try {
					fmem = MapViewOfFile(fmap,
						(action != ACTION_DRYRUN ?
							FILE_MAP_WRITE : FILE_MAP_READ),
						0, 0, 0);

					GLE_FAIL_IF(!fmem, "MapViewOfFile");

					// CheckSumMappedFile is not thread-safe
					IMAGE_NT_HEADERS* hdr = CheckSumMappedFile(fmem, fsize, before,
						after);

					GLE_FAIL_IF(!hdr, "CheckSumMappedFile");

					if (*before == *after)
						return true;

					if (hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
						if (action != ACTION_DRYRUN) {
							((IMAGE_NT_HEADERS64*)hdr)->OptionalHeader.CheckSum = *after;
						}
					}
					else if (hdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
						if (action != ACTION_DRYRUN) {
							((IMAGE_NT_HEADERS32*)hdr)->OptionalHeader.CheckSum = *after;
						}
					}
					else {
						FAIL("Invalid PE file: Invalid header magic");
					}

					if (action != ACTION_DRYRUN) {
						GLE_FAIL_IF(!FlushViewOfFile(fmem, 0), "FlushViewOfFile");
						GLE_FAIL_IF(!FlushFileBuffers(f), "FlushFileBuffers");
					}
				}
				__finally {
					if (fmem)
						UnmapViewOfFile(fmem);
				}
			}
			__finally {
				if (fmap)
					CloseHandle(fmap);
			}
		}
		__finally {
			if (f != INVALID_HANDLE_VALUE)
				CloseHandle(f);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		FAIL("An exception occurred");
	}

	return true;
}

/*
PathIsBanned checks if the path contains banned characters.
https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247.aspx
Returns true if a banned character was found.
*/
bool PathIsBanned(const wchar_t* path)
{
	for (const wchar_t* p = path; *p; ++p) {
		if (1 <= *p && *p <= 31)
			return true;

		for (wchar_t* banned = L"|<>\"?*"; *banned; ++banned) {
			if (*p == *banned)
				return true;
		}
	}

	return false;
}

void ShowUsageAndQuit()
{
	fprintf(stderr,
		"\n"
		"Usage: FixPEChecksum [--no-csv-header] [--dryrun] [--] <file> [[file]...]\n"
		"\n"
		"FixPEChecksum fixes the PE checksum in 32-bit and 64-bit PE files.\n"
		"\n"
		"Options must come before files and may be explicitly ended with --.\n"
		"\n"
		"Output is in CSV format: Before,After,Filename\n"
		"\n"
		"Filename in CSV output is always quoted. If Filename was processed\n"
		"successfully then Before and After contain the checksum as a hex DWORD\n"
		"prefixed with 0x. If Filename was not processed successfully then Before\n"
		"and After are empty.\n"
		"\n"
		"The exit code is equal to how many files failed processing.\n"
		"\n"
		"Copyright (C) 2018 Jay Satiro <raysatiro@yahoo.com>\n"
		"All rights reserved. License GPLv3+: GNU GPL version 3 or later\n"
		"<http://www.gnu.org/licenses/gpl.html>.\n"
		"This is free software: you are free to change and redistribute it.\n"
		"There is NO WARRANTY, to the extent permitted by law.\n"
		"\n"
		"https://gist.github.com/jay/d662cc9615f3e1ffc75e4ae9485da685\n"
	);
	exit(1);
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
	(void)envp;

	int i;
	int errcnt = 0;
	bool header = true;
	action action = ACTION_FIX;

	if (argc <= 1)
		ShowUsageAndQuit();

	for (i = 1; i < argc; ++i) {
		if (!wcscmp(L"--", argv[i])) {
			++i;
			break;
		}

		if (!wcscmp(L"--help", argv[i]))
			ShowUsageAndQuit();
		else if (!wcscmp(L"--csv-header", argv[i]))
			header = true;
		else if (!wcscmp(L"--no-csv-header", argv[i]))
			header = false;
		else if (!wcscmp(L"--dryrun", argv[i]) ||
			!wcscmp(L"--dry-run", argv[i]))
			action = ACTION_DRYRUN;
		else if (!wcscmp(L"--no-dryrun", argv[i]) ||
			!wcscmp(L"--no-dry-run", argv[i]))
			action = ACTION_FIX;
		else
			break;
	}

	if (header)
		wprintf(L"Before,After,Filename\n");

	for (; i < argc; ++i) {
		const wchar_t* filename = argv[i];

		/* Skip paths with double quotes because that would mess up the CSV
		   output, and besides they're a banned filename character in Windows. */
		if (PathIsBanned(filename)) {
			fwprintf(stderr, L"Error: Filename has banned character, ignoring.\n");
			fwprintf(stderr, L"Filename: %s\n", filename);
			++errcnt;
			continue;
		}

		DWORD before, after;

		if (!FixPEChecksum(filename, action, &before, &after)) {
			wprintf(L",,\"%s\"\n", filename);
			++errcnt;
			continue;
		}

		wprintf(L"0x%08X,0x%08X,\"%s\"\n", before, after, filename);
	}

	return errcnt;
}