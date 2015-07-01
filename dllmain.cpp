// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <windows.h>
#include <Ntsecapi.h>
#include "detours.h"
#include <syelog.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>

#pragma comment(lib, "detours")
#pragma comment(lib, "syelog")

#define DEBUG 1

//#define PRINT2CONSOLE 1
#define SYELOG 1
//#define OUTPUT2FILE 1

#ifdef PRINT2CONSOLE
	#define OUTPUTME(...) printf(__VA_ARGS__)
	//#define OUTPUTME(...) wprintf(__VA_ARGS__)
#elif SYELOG
	#define OUTPUTME(...) Syelog(SYELOG_SEVERITY_NOTICE, __VA_ARGS__)
#elif OUTPUT2FILE
	#define OUTPUTME(...) fprintf(ofp, __VA_ARGS__)
#endif

extern "C" {

    HANDLE ( WINAPI *
             Real_CreateFileW)(LPCWSTR a0,
                               DWORD a1,
                               DWORD a2,
                               LPSECURITY_ATTRIBUTES a3,
                               DWORD a4,
                               DWORD a5,
                               HANDLE a6)
        = CreateFileW;

    BOOL ( WINAPI *
           Real_WriteFile)(HANDLE hFile,
                           LPCVOID lpBuffer,
                           DWORD nNumberOfBytesToWrite,
                           LPDWORD lpNumberOfBytesWritten,
                           LPOVERLAPPED lpOverlapped)
        = WriteFile;
    BOOL ( WINAPI *
           Real_FlushFileBuffers)(HANDLE hFile)
        = FlushFileBuffers;
    BOOL ( WINAPI *
           Real_CloseHandle)(HANDLE hObject)
        = CloseHandle;

    BOOL ( WINAPI *
           Real_WaitNamedPipeW)(LPCWSTR lpNamedPipeName, DWORD nTimeOut)
        = WaitNamedPipeW;
    BOOL ( WINAPI *
           Real_SetNamedPipeHandleState)(HANDLE hNamedPipe,
                                         LPDWORD lpMode,
                                         LPDWORD lpMaxCollectionCount,
                                         LPDWORD lpCollectDataTimeout)
        = SetNamedPipeHandleState;

    DWORD ( WINAPI *
            Real_GetCurrentProcessId)(VOID)
        = GetCurrentProcessId;
    VOID ( WINAPI *
           Real_GetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime)
        = GetSystemTimeAsFileTime;

    VOID ( WINAPI *
           Real_InitializeCriticalSection)(LPCRITICAL_SECTION lpSection)
        = InitializeCriticalSection;
    VOID ( WINAPI *
           Real_EnterCriticalSection)(LPCRITICAL_SECTION lpSection)
        = EnterCriticalSection;
    VOID ( WINAPI *
           Real_LeaveCriticalSection)(LPCRITICAL_SECTION lpSection)
        = LeaveCriticalSection;
}

DWORD WINAPI CreateProcessInternalW(
  __in         DWORD unknown1,                              // always (?) NULL
  __in_opt     LPCTSTR lpApplicationName,
  __inout_opt  LPTSTR lpCommandLine,
  __in_opt     LPSECURITY_ATTRIBUTES lpProcessAttributes,
  __in_opt     LPSECURITY_ATTRIBUTES lpThreadAttributes,
  __in         BOOL bInheritHandles,
  __in         DWORD dwCreationFlags,
  __in_opt     LPVOID lpEnvironment,
  __in_opt     LPCTSTR lpCurrentDirectory,
  __in         LPSTARTUPINFO lpStartupInfo,
  __out        LPPROCESS_INFORMATION lpProcessInformation,
  __in         DWORD unknown2                               // always (?) NULL
);

__declspec(dllexport) VOID __cdecl dummy()
{
	return;
}

typedef DWORD (WINAPI *_CreateProcessInternalW)(DWORD unknown1, LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, DWORD unknown2);
static _CreateProcessInternalW original_CreateProcessInternalW;

typedef NTSTATUS (WINAPI *_ZwAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
static _ZwAllocateVirtualMemory original_ZwAllocateVirtualMemory;

typedef NTSTATUS (WINAPI *_ZwWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
static _ZwWriteVirtualMemory original_ZwWriteVirtualMemory;

typedef enum _SECTION_INHERIT {
    ViewShare=1,
    ViewUnmap=2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef NTSTATUS (WINAPI *_ZwMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
static _ZwMapViewOfSection original_ZwMapViewOfSection;

typedef NTSTATUS (WINAPI* _NtUnmapViewOfSection)(HANDLE ProcessHandle,	PVOID BaseAddress);
static _NtUnmapViewOfSection original_NtUnmapViewOfSection;

typedef NTSTATUS (WINAPI *_NtGetContextThread)(HANDLE ThreadHandle, PCONTEXT pContext );
static _NtGetContextThread original_NtGetContextThread;

typedef NTSTATUS (WINAPI *_NtSetContextThread)(HANDLE ThreadHandle, PCONTEXT pContext );
static _NtSetContextThread original_NtSetContextThread;

typedef NTSTATUS (WINAPI *_ZwResumeProcess)(HANDLE ProcessHandle);
static _ZwResumeProcess original_ZwResumeProcess;

typedef NTSTATUS (WINAPI *_ZwResumeThread)(HANDLE ThreadHandle, PULONG 	SuspendCount);
static _ZwResumeThread original_ZwResumeThread;

typedef NTSTATUS (WINAPI *_NtAlertResumeThread)(HANDLE ThreadHandle, PULONG SuspendCount);
static _NtAlertResumeThread original_NtAlertResumeThread;

typedef NTSTATUS (WINAPI *_ZwTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
static _ZwTerminateProcess original_ZwTerminateProcess;

HANDLE rProcessHandle;
HANDLE rThreadHandle;

LPVOID r_lpAddress;
DWORD r_Size;
DWORD gDumpCounter;
DWORD g_PrevWriteProcessMemory;
BOOL bInjected= false;
LPCVOID glpBuffer;
DWORD g_r_Size;
LPVOID g_r_lpAddress;

__forceinline void AttachtoDebuggernow()
{
	__asm
   {
      int 3
   }
}

__forceinline void loopmenow()
{
start:
	goto start;
}

VOID DumpMemory(HANDLE hProcess, LPVOID lpTargetAddr, DWORD bSize, LPVOID lpNewImageBase, bool fixme)
{
	CHAR	szFilePath[MAX_PATH + 1];
	HANDLE	hFile;
	DWORD	bWritten= 0;
	CHAR    *bBuffer= NULL;

	#ifdef DEBUG
	OUTPUTME("DumpMemory process handle %08x\n\tAddress= %08x\n\tsize= %d\n" , hProcess, lpTargetAddr, bSize);
	#endif

	if (lpTargetAddr == NULL || bSize == 0){
		#ifdef DEBUG
		OUTPUTME("DumpMemory(): Not dumping now.\n");
		#endif
		return;
	}

	bBuffer= (CHAR*) calloc(1, bSize);
	if (!bBuffer){
		#ifdef DEBUG
		OUTPUTME("Error in allocating memory.");
		#endif
		return;
	}

	if (hProcess != NULL){
		if(!ReadProcessMemory(hProcess, lpTargetAddr, bBuffer, bSize, &bWritten)){
			free(bBuffer);
			bBuffer= NULL;
			#ifdef DEBUG
			OUTPUTME("Error in reading memory.");
			#endif
			return;
		}
	} else {
		int index=0;
		__try
        {
            for(index=0; index < bSize; index++){
				//printf("index= %d\n", index);
				bBuffer[index]= ((char*)lpTargetAddr)[index];
			}
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
			#ifdef DEBUG
            OUTPUTME("Exception handler %lX\n", _exception_code()); 
			#endif
            //Sleep(2000);
        }

		bSize= index;
		//bBuffer= (CHAR*)lpTargetAddr;
	}

	if (bSize > 1024){
		// Lets do a fix.
		PIMAGE_DOS_HEADER pidosh = (PIMAGE_DOS_HEADER)bBuffer;
		if (pidosh->e_magic == 0x5A4D){
			PIMAGE_NT_HEADERS pinth = (PIMAGE_NT_HEADERS)((BYTE*)pidosh + pidosh->e_lfanew);
			if( pinth->Signature == 0x4550){
				
				PIMAGE_OPTIONAL_HEADER pioh = (PIMAGE_OPTIONAL_HEADER)&pinth->OptionalHeader;
				#ifdef DEBUG
				OUTPUTME("Imagebase= %08x\n", pioh->ImageBase);
				#endif
				if (pioh->ImageBase == (DWORD)lpNewImageBase){
					#ifdef DEBUG
					OUTPUTME("ImageBase is same\n");
					#endif
					if (fixme)
						pioh->ImageBase= 0x00400000;
				}
			}
		}
		

		//PIMAGE_FILE_HEADER pifh = (PIMAGE_FILE_HEADER)&pinth->FileHeader;
		//
	}

	_snprintf(szFilePath, MAX_PATH, "ph_%08x_%08x_%d.exe_", hProcess, (DWORD) lpTargetAddr, gDumpCounter++);

	hFile = CreateFileA(szFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if(hFile == INVALID_HANDLE_VALUE) {
		#ifdef DEBUG
		OUTPUTME("Error in dumping the memory\n");
		#endif
		return;
	}

	#ifdef DEBUG
	OUTPUTME("DumpMemory \n\tbSize= %d\n" , bSize);
	#endif
	WriteFile(hFile, bBuffer, bSize, &bWritten, NULL);

	CloseHandle(hFile);
	if(bBuffer)
		free(bBuffer);
}

static DWORD WINAPI HookedCreateProcessInternalW(DWORD unknown1, LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, DWORD unknown2)
{
	DWORD	retvalue;

	if( dwCreationFlags & CREATE_SUSPENDED){
		//loopmenow();
		if (lpCommandLine != NULL){
			#ifdef DEBUG
			DWORD length= wcslen(lpCommandLine) + 2;
			char *MB = (char *)calloc( 1, length );
			if (MB){
				wcstombs(MB, lpCommandLine, length);
				OUTPUTME("Creating process in suspended stage: %s\n" , MB);
				free(MB);
			}
			#endif
		} else {
			#ifdef DEBUG
			DWORD length= wcslen(lpApplicationName) + 2;
			char *MB = (char *)calloc( 1, length );
			if (MB){
				wcstombs(MB, lpApplicationName, length);
				OUTPUTME("Creating process/app in suspended stage: %s\n" , MB);
				free(MB);
			}
			#endif
		}
	}

	//Syelog(SYELOG_SEVERITY_NOTICE, "Hooked CreateProcessInternalW(): %s", asciistr);
	retvalue = original_CreateProcessInternalW(unknown1, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, unknown2);

	if( dwCreationFlags & CREATE_SUSPENDED){
		#ifdef DEBUG
		OUTPUTME("\tCreated processes process handle %08x\n" , lpProcessInformation->hProcess);
		OUTPUTME("\tCreated processes thread handle %08x\n" , lpProcessInformation->hThread);
		#endif

		rProcessHandle= lpProcessInformation->hProcess;
		rThreadHandle= lpProcessInformation->hThread;

		//AttachtoDebuggernow();
		//loopmenow();
		
	}
	
	
	return retvalue;
}

NTSTATUS WINAPI HookedZwMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
	if ((ProcessHandle != (HANDLE)-1) && ProcessHandle != ::GetCurrentProcess()){
		#ifdef DEBUG
		OUTPUTME("ZwMapViewOfSection on a remote process handle %08x\n\tAddress= %08x\n\tSectionOffset= %08x\n\tViewSize= %08x\n\tAllocationType= %08x\n\tWin32Protect= %08x\n" , ProcessHandle, *BaseAddress, SectionOffset, ViewSize, AllocationType, Win32Protect);
		#endif
		//loopmenow();

		__try
		{
			DWORD local_BaseAddress= 0;
			LARGE_INTEGER local_sectionoffset;
			SIZE_T local_viewsize= 0;

			if(SectionOffset){
				local_sectionoffset.HighPart = SectionOffset->HighPart;
				local_sectionoffset.LowPart = SectionOffset->LowPart;
			}
			
			NTSTATUS returnvalue= original_ZwMapViewOfSection(SectionHandle, GetCurrentProcess(), 
				                                              (PVOID *)&local_BaseAddress, ZeroBits, 
															  CommitSize, 
															  SectionOffset == NULL? NULL: &local_sectionoffset, 
															  &local_viewsize, InheritDisposition, 
															  AllocationType, Win32Protect);

			#ifdef DEBUG
				OUTPUTME("After our mapping processHandle= %08x\n\tAddress= %08x\n\ViewSize= %08x\n\tAllocationType= %08x\n\tWin32Protect= %08x\n" , ProcessHandle, local_BaseAddress,  local_viewsize, AllocationType, Win32Protect);
			#endif

			if(returnvalue == 0){
				DumpMemory(NULL, (LPVOID)local_BaseAddress, local_viewsize, (LPVOID)0x0 /* FIXME */, FALSE);
			} else {
				#ifdef DEBUG
					OUTPUTME("Failed to map the section. %lX\n", returnvalue); 
				#endif
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			#ifdef DEBUG
			   OUTPUTME("Exception handler(@ HookedZwMapViewOfSection) %lX\n", _exception_code()); 
			#endif
			//Sleep(2000);
		}
	}

	return original_ZwMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}


NTSTATUS WINAPI Hooked_NtUnmapViewOfSection(HANDLE ProcessHandle,	PVOID BaseAddress)
{
	if ((ProcessHandle != GetCurrentProcess()) && ProcessHandle != ::GetCurrentProcess()){
		#ifdef DEBUG
		OUTPUTME("NtUnmapViewOfSection on a remote process handle %08x \n\tAddress= %08x\n" , ProcessHandle, BaseAddress);
		#endif
		//loopmenow();
	}
	
	return original_NtUnmapViewOfSection(ProcessHandle, BaseAddress);
}

NTSTATUS WINAPI HookedZwAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
	PVOID	lpAddr= 0x0;
	NTSTATUS returnValue= 0; //STATUS_SUCCESS

	if ((ProcessHandle != (HANDLE)-1) && ProcessHandle != ::GetCurrentProcess() && (*RegionSize > 4 * 4 * 1024)){
		#ifdef DEBUG
		OUTPUTME("ZwAllocateVirtualMemory on a remote process handle %08x\n\tAddress= %08x\n\tsize= %d\n" , ProcessHandle, *BaseAddress, *RegionSize);
		#endif
		lpAddr= *BaseAddress;
	}

	returnValue= original_ZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

	if (returnValue == 0 && (ProcessHandle != (HANDLE)-1) && ProcessHandle != ::GetCurrentProcess() && (*RegionSize > 4 * 4 * 1024) ){
		#ifdef DEBUG
		OUTPUTME("ZwAllocateVirtualMemory(Return) on a remote process handle %08x\n\tAddress= %08x\n\tsize= %d\n\treturn=0x%08x\n" , ProcessHandle, *BaseAddress, *RegionSize, returnValue);
		#endif
		r_lpAddress= *BaseAddress;
		r_Size= *RegionSize;

		//if (lpAddr== *BaseAddress)
		//	;//loopmenow();
	}

	//AttachtoDebuggernow();
	//loopmenow();
	return returnValue;
}

NTSTATUS WINAPI HookedZwWriteVirtualMemory(HANDLE ProcessHandle, PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
	if (ProcessHandle != ::GetCurrentProcess() /*&& nSize > 4*/){
		#ifdef DEBUG
		//OUTPUTME("WriteProcessMemory on a remote process handle %08x\n\tAddress= %08x\n\tsize= %d\n" , ProcessHandle, lpBaseAddress, nSize);
		#endif
		//if (nSize == 4){
			// current write size is 4.
			//if (g_PrevWriteProcessMemory != nSize){
			if (r_lpAddress == lpBaseAddress) {
				#ifdef DEBUG
				OUTPUTME("ZwWriteVirtualMemory on a remote process handle %08x\n\tLocal Address= %08x\n\tRemote Address= %08x\n\tsize= %d\n" , ProcessHandle, lpBuffer, lpBaseAddress, nSize);
				#endif
				//DumpMemory(rProcessHandle, r_lpAddress, r_Size);
				// or you can save these addresses and get the dump in the resumethread()
				glpBuffer= lpBuffer;
				g_r_Size= r_Size;
				g_r_lpAddress= r_lpAddress;
				DumpMemory(NULL, (LPVOID)lpBuffer, r_Size, (LPVOID)r_lpAddress, TRUE);
				DumpMemory(NULL, (LPVOID)lpBuffer, r_Size, (LPVOID)r_lpAddress, FALSE);
			}
		//}
		g_PrevWriteProcessMemory= nSize;
	}
	return original_ZwWriteVirtualMemory(ProcessHandle, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

NTSTATUS WINAPI HookedNtGetContextThread(HANDLE ThreadHandle, PCONTEXT pContext )
{
	if (ThreadHandle == rThreadHandle){
		#ifdef DEBUG
		OUTPUTME("Getting the Thread context of the remote handle %08x\n", ThreadHandle);
		#endif
	}
	return original_NtGetContextThread(ThreadHandle, pContext);
}

NTSTATUS WINAPI HookedNtSetContextThread(HANDLE ThreadHandle, PCONTEXT pContext )
{
	if (ThreadHandle == rThreadHandle){
		#ifdef DEBUG
		OUTPUTME("Setting the Thread context of the remote handle %08x\n", ThreadHandle);
		#endif
	}
	return original_NtSetContextThread(ThreadHandle, pContext);
}

static NTSTATUS WINAPI HookedZwTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
	#ifdef DEBUG
	OUTPUTME("Terminating the process.\n\tProcessHandle= %08x\n\tExitStatus= %08x\n", ProcessHandle, ExitStatus);
	#endif
	return original_ZwTerminateProcess(ProcessHandle, ExitStatus);
}

NTSTATUS WINAPI HookedZwResumeThread(HANDLE ThreadHandle, PULONG 	SuspendCount)
{
	if (ThreadHandle == rThreadHandle){
		#ifdef DEBUG
		OUTPUTME("Resuming the Thread using ZwResumeThread() of the remote handle %08x\n", ThreadHandle);
		#endif
		DumpMemory(NULL, (LPVOID)glpBuffer, g_r_Size, (LPVOID)g_r_lpAddress, FALSE);
	}

	return original_ZwResumeThread(ThreadHandle, SuspendCount);
}


NTSTATUS WINAPI HookedNtAlertResumeThread(HANDLE ThreadHandle, PULONG SuspendCount)
{
	if (ThreadHandle == rThreadHandle){
		#ifdef DEBUG
		OUTPUTME("Resuming the Thread using NtAlertResumeThread() of the remote handle %08x\n", ThreadHandle);
		#endif
		DumpMemory(NULL, (LPVOID)glpBuffer, g_r_Size, (LPVOID)g_r_lpAddress, FALSE);
	}

	return original_NtAlertResumeThread(ThreadHandle, SuspendCount);
	//return false;
}


#define BUF_SIZE 2048
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG error;
    (void)hinst;
    (void)reserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();

		/*CHAR buffer[BUF_SIZE];
		if(GetModuleFileNameA(NULL,&buffer[0],sizeof(buffer)) == ERROR_INSUFFICIENT_BUFFER){
			buffer[BUF_SIZE-1]= '\0';
			//Syelog(SYELOG_SEVERITY_NOTICE, "Not injection any hooks to %s", buffer);
			return TRUE;
		}

		buffer[BUF_SIZE-1]= '\0';
		if(false && strstr(buffer, "runme") == NULL){
			//Syelog(SYELOG_SEVERITY_NOTICE, "I am not interested in this process. %s", buffer);
			return TRUE;
		}*/

		#ifdef SYELOG
		SyelogOpen("runpedmp", SYELOG_FACILITY_APPLICATION);		
		#endif
		
		if (!original_CreateProcessInternalW){
			original_CreateProcessInternalW= (_CreateProcessInternalW)::GetProcAddress(::LoadLibraryW(L"kernel32.dll"), "CreateProcessInternalW");
			OUTPUTME("CreateProcessInternalW() @ 0x%08x\n", original_CreateProcessInternalW);
		}

		if(!original_NtUnmapViewOfSection){
			original_NtUnmapViewOfSection= (_NtUnmapViewOfSection)::GetProcAddress(::LoadLibraryW(L"ntdll.dll"), "NtUnmapViewOfSection");
			OUTPUTME("NtUnmapViewOfSection() @ 0x%08x\n", original_NtUnmapViewOfSection);
		}

		if(!original_ZwAllocateVirtualMemory){
			original_ZwAllocateVirtualMemory= (_ZwAllocateVirtualMemory)::GetProcAddress(::LoadLibraryW(L"ntdll.dll"), "ZwAllocateVirtualMemory");
			OUTPUTME("ZwAllocateVirtualMemory() @ 0x%08x\n", original_ZwAllocateVirtualMemory);
		}

		if(!original_ZwWriteVirtualMemory){
			original_ZwWriteVirtualMemory= (_ZwWriteVirtualMemory)::GetProcAddress(::LoadLibraryW(L"ntdll.dll"), "ZwWriteVirtualMemory");
			OUTPUTME("ZwWriteVirtualMemory() @ 0x%08x\n", original_ZwWriteVirtualMemory);
		}

		if(!original_NtGetContextThread){
			original_NtGetContextThread= (_NtGetContextThread)::GetProcAddress(::LoadLibraryW(L"ntdll.dll"), "NtGetContextThread");
			OUTPUTME("NtGetContextThread() @ 0x%08x\n", original_NtGetContextThread);
		}

		if(!original_NtSetContextThread){
			original_NtSetContextThread= (_NtSetContextThread)::GetProcAddress(::LoadLibraryW(L"ntdll.dll"), "NtSetContextThread");
			OUTPUTME("NtSetContextThread() @ 0x%08x\n", original_NtSetContextThread);
		}

		if(!original_ZwResumeThread){
			original_ZwResumeThread= (_ZwResumeThread)::GetProcAddress(::LoadLibraryW(L"ntdll.dll"), "ZwResumeThread");
			OUTPUTME("ZwResumeThread() @ 0x%08x\n", original_ZwResumeThread);
		}
		
		if(!original_NtAlertResumeThread){
			original_NtAlertResumeThread= (_NtAlertResumeThread)::GetProcAddress(::LoadLibraryW(L"ntdll.dll"), "NtAlertResumeThread");
			OUTPUTME("NtAlertResumeThread() @ 0x%08x\n", original_NtAlertResumeThread);
		}

		if(!original_ZwMapViewOfSection){
			original_ZwMapViewOfSection= (_ZwMapViewOfSection)::GetProcAddress(::LoadLibraryW(L"ntdll.dll"), "ZwMapViewOfSection");
			OUTPUTME("ZwMapViewOfSection() @ 0x%08x\n", original_ZwMapViewOfSection);
		}

		if(!original_ZwTerminateProcess){
			original_ZwTerminateProcess= (_ZwTerminateProcess)::GetProcAddress(::LoadLibraryW(L"ntdll.dll"), "ZwTerminateProcess");
			OUTPUTME("ZwTerminateProcess() @ 0x%08x\n", original_ZwTerminateProcess);
		}

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)original_CreateProcessInternalW, HookedCreateProcessInternalW);
		DetourAttach(&(PVOID&)original_ZwAllocateVirtualMemory, HookedZwAllocateVirtualMemory);
		DetourAttach(&(PVOID&)original_ZwWriteVirtualMemory, HookedZwWriteVirtualMemory);
		DetourAttach(&(PVOID&)original_ZwMapViewOfSection, HookedZwMapViewOfSection);
		DetourAttach(&(PVOID&)original_NtUnmapViewOfSection, Hooked_NtUnmapViewOfSection);
		DetourAttach(&(PVOID&)original_NtGetContextThread, HookedNtGetContextThread);
		DetourAttach(&(PVOID&)original_NtSetContextThread, HookedNtSetContextThread);
		DetourAttach(&(PVOID&)original_NtAlertResumeThread, HookedNtAlertResumeThread);
		DetourAttach(&(PVOID&)original_ZwResumeThread, HookedZwResumeThread);
		DetourAttach(&(PVOID&)original_ZwTerminateProcess, HookedZwTerminateProcess);
		error = DetourTransactionCommit();

        if (error == NO_ERROR) {
			#ifdef DEBUG
			OUTPUTME("All the hooks are installed\n");
			#endif
        }
        else {
			#ifdef DEBUG
			OUTPUTME("Error occurred while initializing Hook (GLE: %d)", GetLastError());
			#endif
        }

		bInjected= true;

    }
    else if (dwReason == DLL_PROCESS_DETACH) {
		if (!bInjected)
			return TRUE;
		
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)original_CreateProcessInternalW, HookedCreateProcessInternalW);
		DetourDetach(&(PVOID&)original_ZwAllocateVirtualMemory, HookedZwAllocateVirtualMemory);
		DetourDetach(&(PVOID&)original_ZwWriteVirtualMemory, HookedZwWriteVirtualMemory);
		DetourDetach(&(PVOID&)original_ZwMapViewOfSection, HookedZwMapViewOfSection);
		DetourDetach(&(PVOID&)original_NtUnmapViewOfSection, Hooked_NtUnmapViewOfSection);
		DetourDetach(&(PVOID&)original_NtGetContextThread, HookedNtGetContextThread);
		DetourDetach(&(PVOID&)original_NtSetContextThread, HookedNtSetContextThread);
		DetourDetach(&(PVOID&)original_NtAlertResumeThread, HookedNtAlertResumeThread);
		DetourDetach(&(PVOID&)original_ZwResumeThread, HookedZwResumeThread);
		DetourDetach(&(PVOID&)original_ZwTerminateProcess, HookedZwTerminateProcess);
		error = DetourTransactionCommit();
		if (error == NO_ERROR) {
			#ifdef DEBUG
			OUTPUTME("All the hooks are uninstalled\n");
			#endif
        }
        else {
			#ifdef DEBUG
			OUTPUTME("Error occurred while uninitializing Hook (GLE: %d)", GetLastError());
			#endif
        }

		#ifdef SYELOG
		SyelogClose(false);
		#endif
    }
    return TRUE;
}
