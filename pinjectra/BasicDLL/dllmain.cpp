#pragma once
// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>

extern void doStuff(char* argument) {
	printf("doSuff called\n");
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	printf("DllMain has been called\n");
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

