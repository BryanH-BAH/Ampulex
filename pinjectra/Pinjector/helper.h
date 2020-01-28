#pragma once
#define _WIN32_DCOM
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <vector>
#include <tlhelp32.h>
#pragma comment(lib, "wbemuuid.lib")

int getPID(std::wstring processName) {

	std::vector<DWORD> pids;
	std::wstring targetProcessName = processName;

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //all processes

	PROCESSENTRY32W entry; //current process
	entry.dwSize = sizeof entry;

	if (!Process32FirstW(snap, &entry)) { //start with the first in snapshot
		return 0;
	}

	do {
		if (std::wstring(entry.szExeFile) == targetProcessName) {
			pids.push_back(entry.th32ProcessID); //name matches; add to list
		}
	} while (Process32NextW(snap, &entry)); //keep going until end of snapshot

	//for (int i(0); i < pids.size(); ++i) {
	//	std::cout << pids[i] << std::endl;
	//}
	return pids[0];
}


std::vector<DWORD64> EnumThreads(std::wstring processName)
{
	auto targetPID = getPID(processName);
	std::vector<DWORD64> results;

	HRESULT hres;

	// Step 1: --------------------------------------------------
	// Initialize COM. ------------------------------------------

	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres))
	{
		std::cout << "Failed to initialize COM library. Error code = 0x"
			<< std::hex << hres << std::endl;
		throw "Failed to init COM";
	}

	// Step 2: --------------------------------------------------
	// Set general COM security levels --------------------------

	hres = CoInitializeSecurity(
		NULL,
		-1,                          // COM authentication
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		NULL                         // Reserved
	);


	if (FAILED(hres))
	{
		std::cout << "Failed to initialize security. Error code = 0x"
			<< std::hex << hres << std::endl;
		CoUninitialize();
		throw "Failed to init security";
		//return 1;                    // Program has failed.
	}

	// Step 3: ---------------------------------------------------
	// Obtain the initial locator to WMI -------------------------

	IWbemLocator* pLoc = NULL;

	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)& pLoc);

	if (FAILED(hres))
	{
		std::cout << "Failed to create IWbemLocator object."
			<< " Err code = 0x"
			<< std::hex << hres << std::endl;
		CoUninitialize();
		throw "Failed to create IWbenLocator obj";
		//return 1;                 // Program has failed.
	}

	// Step 4: -----------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method

	IWbemServices* pSvc = NULL;

	// Connect to the root\cimv2 namespace with
	// the current user and obtain pointer pSvc
	// to make IWbemServices calls.
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
		NULL,                    // User name. NULL = current user
		NULL,                    // User password. NULL = current
		0,                       // Locale. NULL indicates current
		NULL,                    // Security flags.
		0,                       // Authority (for example, Kerberos)
		0,                       // Context object 
		&pSvc                    // pointer to IWbemServices proxy
	);

	if (FAILED(hres))
	{
		std::cout << "Could not connect. Error code = 0x"
			<< std::hex << hres << std::endl;
		pLoc->Release();
		CoUninitialize();
		throw "Can't connect";
		//return 1;                // Program has failed.
	}

	std::cout << "Connected to ROOT\\CIMV2 WMI namespace" << std::endl;


	// Step 5: --------------------------------------------------
	// Set security levels on the proxy -------------------------

	hres = CoSetProxyBlanket(
		pSvc,                        // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
		NULL,                        // Server principal name 
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities 
	);

	if (FAILED(hres))
	{
		std::cout << "Could not set proxy blanket. Error code = 0x"
			<< std::hex << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		throw "Can't set proxy blanket";
		//return 1;               // Program has failed.
	}

	// Step 6: --------------------------------------------------
	// Use the IWbemServices pointer to make requests of WMI ----

	// https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/cim-thread (parent)
	// https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-thread (what we're playing with)
	const char* queryTemplate = "SELECT * FROM Win32_Thread WHERE ProcessHandle='%d'";
	size_t szQueryTemplate = (std::strlen(queryTemplate) - 2) + sizeof(DWORD64);
	char* qBuf = new char[szQueryTemplate];
	auto retVal = sprintf_s(qBuf, szQueryTemplate, queryTemplate, targetPID);
	std::cout << qBuf << std::endl;

	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t(qBuf),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	if (FAILED(hres))
	{
		std::cout << "Query for operating system name failed."
			<< " Error code = 0x"
			<< std::hex << hres << std::endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		throw "Query Failed";
		//return 1;               // Program has failed.
	}

	// Step 7: -------------------------------------------------
	// Get the data from the query in step 6 -------------------

	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;

	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
			&pclsObj, &uReturn);

		if (0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;

		// Get the value of the Name property

		hr = pclsObj->Get(L"ProcessHandle", 0, &vtProp, 0, 0);
		auto pid = _wtoi(vtProp.bstrVal);
		VariantClear(&vtProp);

		if (pid != targetPID) {
			continue;
		}
		hr = pclsObj->Get(L"ThreadState", 0, &vtProp, 0, 0);
		std::wcout << " ThreadState : " << vtProp.ulVal << std::endl;

		// threadstate
		// https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-thread -- waiting is 5, we want waiting.
		if (vtProp.ulVal == 5) {
			VariantClear(&vtProp);

			hr = pclsObj->Get(L"Handle", 0, &vtProp, 0, 0);
			std::wcout << " TID : " << vtProp.bstrVal << std::endl;
			results.push_back(_wtoi(vtProp.bstrVal));
			VariantClear(&vtProp);
		}
		else {
			VariantClear(&vtProp);
		}
		pclsObj->Release();
	}

	// Cleanup
	// ========

	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();
	delete qBuf;
	return results;   // Program successfully completed.

}

