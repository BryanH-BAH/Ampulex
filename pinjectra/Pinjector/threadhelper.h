//https://stackoverflow.com/questions/22949725/how-to-get-thread-state-e-g-suspended-memory-cpu-usage-start-time-priori

namespace segment {
#define WIN64
#include <Windows.h>
#include <winnt.h>
#include <cassert>
#include <iostream>
#include <winternl.h>
#include <WinBase.h>

#include "helper.h"
	typedef LONG NTSTATUS;

#define STATUS_SUCCESS              ((NTSTATUS) 0x00000000)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS) 0xC0000004)

	enum KWAIT_REASON
	{
		Executive,
		FreePage,
		PageIn,
		PoolAllocation,
		DelayExecution,
		Suspended,
		UserRequest,
		WrExecutive,
		WrFreePage,
		WrPageIn,
		WrPoolAllocation,
		WrDelayExecution,
		WrSuspended,
		WrUserRequest,
		WrEventPair,
		WrQueue,
		WrLpcReceive,
		WrLpcReply,
		WrVirtualMemory,
		WrPageOut,
		WrRendezvous,
		Spare2,
		Spare3,
		Spare4,
		Spare5,
		Spare6,
		WrKernel,
		MaximumWaitReason
	};

	enum THREAD_STATE
	{
		Running = 2,
		Waiting = 5,
	};

#pragma pack(push,8)
	/*
	struct CLIENT_ID
	{
		HANDLE UniqueProcess; // Process ID
		HANDLE UniqueThread;  // Thread ID
	};*/

	// http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/thread.htm
	// Size = 0x40 for Win32
	// Size = 0x50 for Win64
	struct SYSTEM_THREAD
	{
		LARGE_INTEGER KernelTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER CreateTime;
		ULONG         WaitTime;
		PVOID         StartAddress;
		CLIENT_ID     ClientID;           // process/thread ids
		LONG          Priority;
		LONG          BasePriority;
		ULONG         ContextSwitches;
		THREAD_STATE  ThreadState;
		KWAIT_REASON  WaitReason;
	};

	struct VM_COUNTERS // virtual memory of process
	{
		ULONG_PTR PeakVirtualSize;
		ULONG_PTR VirtualSize;
		ULONG     PageFaultCount;
		ULONG_PTR PeakWorkingSetSize;
		ULONG_PTR WorkingSetSize;
		ULONG_PTR QuotaPeakPagedPoolUsage;
		ULONG_PTR QuotaPagedPoolUsage;
		ULONG_PTR QuotaPeakNonPagedPoolUsage;
		ULONG_PTR QuotaNonPagedPoolUsage;
		ULONG_PTR PagefileUsage;
		ULONG_PTR PeakPagefileUsage;
	};

	// http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm
	// See also SYSTEM_PROCESS_INROMATION in Winternl.h
	// Size = 0x00B8 for Win32
	// Size = 0x0100 for Win64
	struct SYSTEM_PROCESS
	{
		ULONG          NextEntryOffset; // relative offset
		ULONG          ThreadCount;
		LARGE_INTEGER  WorkingSetPrivateSize;
		ULONG          HardFaultCount;
		ULONG          NumberOfThreadsHighWatermark;
		ULONGLONG      CycleTime;
		LARGE_INTEGER  CreateTime;
		LARGE_INTEGER  UserTime;
		LARGE_INTEGER  KernelTime;
		UNICODE_STRING ImageName;
		LONG           BasePriority;
		PVOID          UniqueProcessId;
		PVOID          InheritedFromUniqueProcessId;
		ULONG          HandleCount;
		ULONG          SessionId;
		ULONG_PTR      UniqueProcessKey;
		VM_COUNTERS    VmCounters;
		ULONG_PTR      PrivatePageCount;
		IO_COUNTERS    IoCounters;   // defined in winnt.h
	};

#pragma pack(pop)

	typedef NTSTATUS(WINAPI* t_NtQueryInfo)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

	class cProcInfo
	{
	public:
		cProcInfo()
		{
#ifdef WIN64
			assert(sizeof(SYSTEM_THREAD) == 0x50 && sizeof(SYSTEM_PROCESS) == 0x100);
#else
			assert(sizeof(SYSTEM_THREAD) == 0x40 && sizeof(SYSTEM_PROCESS) == 0xB8);
#endif

			mu32_DataSize = 1000;
			mp_Data = NULL;
			mf_NtQueryInfo = NULL;
		}
		virtual ~cProcInfo()
		{
			if (mp_Data) LocalFree(mp_Data);
		}

		// Capture all running processes and all their threads.
		// returns an API or NTSTATUS Error code or zero if successfull
		DWORD Capture()
		{
			if (!mf_NtQueryInfo)
			{
				mf_NtQueryInfo = (t_NtQueryInfo)GetProcAddress(GetModuleHandleA("NtDll.dll"), "NtQuerySystemInformation");
				if (!mf_NtQueryInfo)
					return GetLastError();
			}

			// This must run in a loop because in the mean time a new process may have started 
			// and we need more buffer than u32_Needed !!
			while (true)
			{
				if (!mp_Data)
				{
					mp_Data = (BYTE*)LocalAlloc(LMEM_FIXED, mu32_DataSize);
					if (!mp_Data)
						return GetLastError();
				}

				ULONG u32_Needed = 0;
				NTSTATUS s32_Status = mf_NtQueryInfo(_SYSTEM_INFORMATION_CLASS::SystemProcessInformation, mp_Data, mu32_DataSize, &u32_Needed);

				if (s32_Status == STATUS_INFO_LENGTH_MISMATCH) // The buffer was too small
				{
					mu32_DataSize = u32_Needed + 4000;
					LocalFree(mp_Data);
					mp_Data = NULL;
					continue;
				}
				return s32_Status;
			}
		}

		// Searches a process by a given Process Identifier
		// Capture() must have been called before!
		SYSTEM_PROCESS* FindProcessByPid(DWORD u32_PID)
		{
			if (!mp_Data)
			{
				assert(mp_Data);
				return NULL;
			}

			SYSTEM_PROCESS* pk_Proc = (SYSTEM_PROCESS*)mp_Data;
			while (TRUE)
			{
				if ((DWORD)(DWORD_PTR)pk_Proc->UniqueProcessId == u32_PID)
					return pk_Proc;

				if (!pk_Proc->NextEntryOffset)
					return NULL;

				pk_Proc = (SYSTEM_PROCESS*)((BYTE*)pk_Proc + pk_Proc->NextEntryOffset);
			}
		}

		SYSTEM_THREAD* FindThreadByTid(SYSTEM_PROCESS* pk_Proc, DWORD u32_TID)
		{
			if (!pk_Proc)
			{
				assert(pk_Proc);
				return NULL;
			}

			// The first SYSTEM_THREAD structure comes immediately after the SYSTEM_PROCESS structure
			SYSTEM_THREAD* pk_Thread = (SYSTEM_THREAD*)((BYTE*)pk_Proc + sizeof(SYSTEM_PROCESS));

			for (DWORD i = 0; i < pk_Proc->ThreadCount; i++)
			{
				if (pk_Thread->ClientID.UniqueThread == (HANDLE)(DWORD_PTR)u32_TID)
					return pk_Thread;

				pk_Thread++;
			}
			return NULL;
		}

		std::vector<SYSTEM_THREAD> getThreads(DWORD PID) {
			std::vector<SYSTEM_THREAD> answer;
			SYSTEM_PROCESS* pk_Proc = FindProcessByPid(PID);

			if (!pk_Proc)
			{
				assert(pk_Proc);
				return answer;
			}
			SYSTEM_THREAD* pk_Thread = (SYSTEM_THREAD*)((BYTE*)pk_Proc + sizeof(SYSTEM_PROCESS));

			for (DWORD i = 0; i < pk_Proc->ThreadCount; i++)
			{
				answer.push_back(*pk_Thread);
				pk_Thread++;
			}
			return answer;
		}

		BOOL IsThreadSuspended(SYSTEM_THREAD* pk_Thread)
		{
			if (!pk_Thread)
				return ERROR_INVALID_PARAMETER;

			//TODO: I'm not sure that this is the only thread type that you can use.  At least look into WrUser* 
			// Those thread wait types like UserRequest may be in WaitFor*Object(s) mode.  See the PInjectra paper and https://stackoverflow.com/questions/48009277/thread-wait-reasons
			auto pb_Suspended = (pk_Thread->ThreadState == Waiting &&
				(//pk_Thread->WaitReason == WrQueue ||
				 pk_Thread->WaitReason == DelayExecution
					));
			return pb_Suspended;
		}

	private:
		BYTE* mp_Data;
		DWORD       mu32_DataSize;
		t_NtQueryInfo mf_NtQueryInfo;
	};

	// Based on the 32 bit code of Sven B. Schreiber on:
	// http://www.informit.com/articles/article.aspx?p=22442&seqNum=5


	int GetSuspendedThreadID(std::wstring processName)
	{
		int answer;
		cProcInfo i_Proc;
		DWORD u32_Error = i_Proc.Capture();
		if (u32_Error)
		{
			printf("Error 0x%X capturing processes.\n", u32_Error);
			return 0;
		}
		int pid = getPID(processName);
		auto threads = i_Proc.getThreads(pid);
		for (int i = 0; i < threads.size(); i++) {
			bool suspended = i_Proc.IsThreadSuspended(&(threads[i]));
			if (suspended) {
				std::cout << "TID " << (DWORD)threads[i].ClientID.UniqueThread << " is Suspended" << std::endl;
				answer = (DWORD)threads[i].ClientID.UniqueThread;
			}
		}
		std::cout << "Targeting TID " << answer << std::endl;
		/*
		SYSTEM_PROCESS* pk_Proc = i_Proc.FindProcessByPid(2452);
		if (!pk_Proc)
		{
			printf("The process does not exist.\n");
			return 0;
		}

		SYSTEM_THREAD* pk_Thread = i_Proc.FindThreadByTid(pk_Proc, 12360);
		if (!pk_Thread)
		{
			printf("The thread does not exist.\n");
			return 0;
		}

		BOOL b_Suspend;
		i_Proc.IsThreadSuspended(pk_Thread, &b_Suspend);

		if (b_Suspend) printf("The thread is suspended.\n");
		else           printf("The thread is not suspended.\n");
		*/
		return answer;
	}
}
