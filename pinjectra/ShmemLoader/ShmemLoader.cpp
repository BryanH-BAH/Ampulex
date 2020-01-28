#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <winnt.h>
#include "sRDI.h"
#include <fstream>

#define BUF_SIZE 1000000
TCHAR szName[] = TEXT("Local\\My");
TCHAR szMsg[] = TEXT("Message from first process.");


int _tmain(int argc, _TCHAR* argv[])
{

	if (argc != 2) {
		printf("USAGE:\n    ShmemLoader.exe [path to injected dll]\n");
		exit(1);
	}

	HANDLE hMapFile;
	LPCTSTR pBuf;

	hMapFile = CreateFileMapping(
		INVALID_HANDLE_VALUE,    // use paging file
		NULL,                    // default security
		PAGE_EXECUTE_READWRITE,          // read/write access
		0,                       // maximum object size (high-order DWORD)
		BUF_SIZE,                // maximum object size (low-order DWORD)
		szName);                 // name of mapping object

	if (hMapFile == NULL)
	{
		_tprintf(TEXT("Could not create file mapping object (%d).\n"),
			GetLastError());
		return 1;
	}
	pBuf = (LPTSTR)MapViewOfFile(hMapFile,   // handle to map object
		FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, // read/write permission
		0,
		0,
		BUF_SIZE);



	if (pBuf == NULL)
	{
		_tprintf(TEXT("Could not map view of file (%d).\n"),
			GetLastError());

		CloseHandle(hMapFile);

		return 1;
	}

	char* source = NULL;
	std::wstring filename = argv[1];

	LPSTR data;
	DWORD datasize;

	if (!GetFileContents(const_cast<wchar_t *>(filename.c_str()), &data, datasize)) {
		printf("Failed to open file\n");
		exit(1);
	}

	LPSTR finalShellcode = NULL;
	DWORD finalSize;
	DWORD dwOldProtect1 = 0;
	SYSTEM_INFO sysInfo;

	// original attempt
	ConvertToShellcode(data, datasize, (DWORD)HashFunctionName((LPSTR)"doStuff"), (LPVOID)"dave", 5, SRDI_CLEARHEADER, finalShellcode, finalSize);
	std::ofstream outfile("debug.shellcode", std::ofstream::binary);
	outfile.write(finalShellcode, finalSize);
	CopyMemory((PVOID)pBuf, finalShellcode, finalSize);

	//CopyMemory((PVOID)pBuf, data, datasize);
	//CopyMemory((PVOID)pBuf, szMsg, (_tcslen(szMsg) * sizeof(TCHAR)));

	//char* view = (char*)finalShellcode;
	//for (int i = 0; i < finalSize; i++) {
	//	printf("0x%02hhx\n", view[i]);
	//	_getch();
	//}

	_getch();

	UnmapViewOfFile(pBuf);
	CloseHandle(hMapFile);

	return 0;
}