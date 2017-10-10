//*******************************************************************************************************************//
//    __  __                      _ _      _____                               ____                 _             
//   |  \/  |                    (_) |    |  __ \                             |  _ \               | |            
//   | \  / | ___  ___ __ _ _ __  _| | __ | |__) | __ ___   ___ ___  ___ ___  | |_) |_ __ ___  __ _| | _____ _ __ 
//   | |\/| |/ _ \/ __/ _` | '_ \| | |/ / |  ___/ '__/ _ \ / __/ _ \/ __/ __| |  _ <| '__/ _ \/ _` | |/ / _ \ '__|
//   | |  | |  __/ (_| (_| | | | | |   <  | |   | | | (_) | (_|  __/\__ \__ \ | |_) | | |  __/ (_| |   <  __/ |   
//   |_|  |_|\___|\___\__,_|_| |_|_|_|\_\ |_|   |_|  \___/ \___\___||___/___/ |____/|_|  \___|\__,_|_|\_\___|_|   
//                                                                                                                
//	 This project was built as a "proof-of-concept" and nothing else. It is not ment for you to cause damage.
//   Not intended for malicious purposes, but to demonstrate how weak Windows is, and some "antihack" software.
//   NOT all the classes and code have been written by me, those files have no comments on top or the author's name.
//	 The original author of this project is me, Norbert Boros a.k.a Mecanik or Mr.Mecanik
// ------------------------------------------------------------------------------------------------------------------
// Looking for professional AntiHack ? Visit: http://liveguard-security.com/ | https://liveguardmu.com/
//*******************************************************************************************************************//

#include "stdafx.h"
#include "Utils.h"

namespace MecanikInjector
{
	typedef NTSTATUS(NTAPI*p_NtWaitForSingleObject)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
	typedef NTSTATUS(NTAPI*p_NtCreateThreadEx)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
	typedef PIMAGE_NT_HEADERS(NTAPI*p_RtlImageNtHeader)(PVOID ModuleAddress);
	typedef NTSTATUS(NTAPI*p_NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	typedef NTSTATUS(NTAPI*p_NtWaitForAlertByThreadId)(PVOID Address, PLARGE_INTEGER Timeout);
	typedef NTSTATUS(NTAPI*p_NtWow64AllocateVirtualMemory64)(HANDLE ProcessHandle, PULONG64 BaseAddress, ULONG64 ZeroBits, PULONG64 Size, ULONG AllocationType, ULONG Protection);
	typedef NTSTATUS(NTAPI*p_NtWow64QueryInformationProcess64)(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID  ProcessInformation64, ULONG  Length, PULONG ReturnLength OPTIONAL);
	typedef NTSTATUS(NTAPI*p_NtWow64WriteVirtualMemory64)(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONGLONG BufferSize, PULONGLONG NumberOfBytesRead);
	typedef NTSTATUS(NTAPI*p_NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesWrite);
	typedef NTSTATUS(NTAPI*p_NtWow64ReadVirtualMemory64)(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONGLONG BufferSize, PULONGLONG NumberOfBytesRead);
	typedef NTSTATUS(NTAPI*p_NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesRead);
	typedef NTSTATUS(NTAPI*p_NtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

	p_NtWaitForSingleObject						T_NtWaitForSingleObject;
	p_NtCreateThreadEx							T_NtCreateThreadEx;
	p_RtlImageNtHeader							T_RtlImageNtHeader;
	p_NtOpenProcess								T_NtOpenProcess;
	p_NtWaitForAlertByThreadId					T_NtWaitForAlertByThreadId;
	p_NtWow64AllocateVirtualMemory64			T_NtWow64AllocateVirtualMemory64;
	p_NtWow64QueryInformationProcess64			T_NtWow64QueryInformationProcess64;
	p_NtReadVirtualMemory						T_NtReadVirtualMemory;
	p_NtProtectVirtualMemory					T_NtProtectVirtualMemory;
	p_NtWow64WriteVirtualMemory64				T_NtWow64WriteVirtualMemory64;
	p_NtWriteVirtualMemory						T_NtWriteVirtualMemory;
	p_NtWow64ReadVirtualMemory64				T_NtWow64ReadVirtualMemory64;

	MProcessInjector T_MProcessInjector;

	MecanikInjector::MProcessInjector::MProcessInjector()
	{
		this->InternalInit();
	}


	MecanikInjector::MProcessInjector::~MProcessInjector()
	{
	}

	bool MecanikInjector::MProcessInjector::CheckProcessModule(HANDLE ProcessHandle, char* ModulePath)
	{
		HMODULE ModuleTable[1024];
		DWORD BytesReturned = 0, ModuleCount = 0;

		if (EnumProcessModules(ProcessHandle, ModuleTable, sizeof(ModuleTable), &BytesReturned) == 0)
		{
			this->GetSystemMessage("EnumProcessModules");
			return 1;
		}

		for (int n = 0, ModuleCount = (BytesReturned / sizeof(HMODULE)); n < ModuleCount; n++)
		{
			char ModuleFilePath[MAX_PATH];

			if (GetModuleFileNameEx(ProcessHandle, ModuleTable[n], ModuleFilePath, MAX_PATH) != 0)
			{
				if (strcmp(ModuleFilePath, ModulePath) == 0)
				{
					return 1;
				}
			}
		}

		return 0;
	}

	bool MecanikInjector::MProcessInjector::StartProcessNTModule(char* ModulePath, DWORD dwProcessId)
	{
		PIMAGE_NT_HEADERS pINH;
		PIMAGE_DATA_DIRECTORY pIDD;
		PIMAGE_BASE_RELOCATION pIBR;
		char Textbuffer[MAX_PATH] = { 0 };
		FARPROC LoadLibraryAddress = 0;
		NTSTATUS status;
		DWORD i, count;
		LPVOID RemoteMemory = 0;
		HANDLE ProcessHandle = 0, hThread = 0;
		OBJECT_ATTRIBUTES ObjectAttributes;
		CLIENT_ID ClientId;
		InitializeObjectAttributes(&ObjectAttributes, 0, 0, 0, 0);
		ClientId.UniqueProcess	= (PVOID)dwProcessId;
		ClientId.UniqueThread	= 0;

		int iPosition = ListView_GetNextItem(hwndListLog, 0, LVNI_SELECTED);

		if ((LoadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA")) == 0)
		{
			this->GetSystemMessage("LoadLibraryAddress");
			return 0;
		} else {
			sprintf_s(Textbuffer, "[LOG] :: LoadLibraryAddress Found at 0x%08x", (UINT)LoadLibraryAddress);
			SendMessage(hwndListLog, LB_ADDSTRING, iPosition, (LPARAM)Textbuffer);
		}

		if(!NT_SUCCESS(status=T_NtOpenProcess(&ProcessHandle, MAXIMUM_ALLOWED, &ObjectAttributes, &ClientId))) {
			this->GetSystemMessage("NtOpenProcess");
			return 0;
		} 

		iPosition = ListView_GetNextItem(hwndListLog, 0, LVNI_SELECTED);
		SendMessage(hwndListLog, LB_ADDSTRING, iPosition, (LPARAM)"[LOG] :: NtOpenProcess opened process successfully!");

		SIZE_T dwSize = _tcslen(ModulePath) * sizeof(TCHAR);

		if ((RemoteMemory=VirtualAllocEx(ProcessHandle, NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) == 0) {
			this->GetSystemMessage("VirtualAllocEx");
			CloseHandle(ProcessHandle);
			return 0;
		} else {
			iPosition = ListView_GetNextItem(hwndListLog, 0, LVNI_SELECTED);
			SendMessage(hwndListLog, LB_ADDSTRING, iPosition, (LPARAM)"[LOG] :: VirtualAllocEx allocated us memory successfully!");
		}

		if (!NT_SUCCESS(status=T_NtWriteVirtualMemory(ProcessHandle, RemoteMemory, ModulePath, dwSize, NULL))) {
			this->GetSystemMessage("NtWriteVirtualMemory");
			VirtualFreeEx(ProcessHandle, RemoteMemory, 0, MEM_RELEASE);
			CloseHandle(ProcessHandle);
			return 0;
		}

		iPosition = ListView_GetNextItem(hwndListLog, 0, LVNI_SELECTED);
		memset(Textbuffer, 0, sizeof(Textbuffer));
		sprintf_s(Textbuffer, "[LOG] :: Writing into the remote process space at 0x%08x", (UINT)RemoteMemory);
		SendMessage(hwndListLog, LB_ADDSTRING, iPosition, (LPARAM)Textbuffer);

		char MutexName[64];

		wsprintf(MutexName, "MECANIKPROC%d", GetProcessId(ProcessHandle));

		HANDLE MutexHandle = CreateMutex(0, 0, MutexName);

		if (MutexHandle == 0)
		{
			VirtualFreeEx(ProcessHandle, RemoteMemory, dwSize, MEM_RELEASE);
			this->GetSystemMessage("CreateMutex");
			return 0;
		}

		if (!NT_SUCCESS(status = T_NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS_VISTA, NULL, ProcessHandle, (LPTHREAD_START_ROUTINE)LoadLibraryAddress, RemoteMemory, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, NULL, NULL, NULL, NULL))){
			this->GetSystemMessage("NtCreateThreadEx");
			VirtualFreeEx(ProcessHandle, RemoteMemory, 0, MEM_RELEASE);
			CloseHandle(MutexHandle);
			return 0;
		}

		if (WaitForSingleObject(hThread, INFINITE) != WAIT_OBJECT_0)
		{
			VirtualFreeEx(ProcessHandle, RemoteMemory, dwSize, MEM_RELEASE);
			this->GetSystemMessage("WaitForSingleObject");
			CloseHandle(MutexHandle);
			return 0;
		}

		VirtualFreeEx(ProcessHandle, RemoteMemory, dwSize, MEM_RELEASE);
		CloseHandle(MutexHandle);

		return 1;
	}


	bool MecanikInjector::MProcessInjector::StartProcessModule(HANDLE ProcessHandle, char* ModulePath, int ModulePathSize)
	{
		LPVOID RemoteMemory = 0;
		HANDLE RemoteThread = 0;
		FARPROC LoadLibraryAddress = 0;

		if ((RemoteMemory = VirtualAllocEx(ProcessHandle, 0, ModulePathSize, MEM_COMMIT, PAGE_READWRITE)) == 0)
		{
			this->GetSystemMessage("VirtualAllocEx");
			return 0;
		}

		if (WriteProcessMemory(ProcessHandle, RemoteMemory, ModulePath, ModulePathSize, 0) == 0)
		{
			VirtualFreeEx(ProcessHandle, RemoteMemory, ModulePathSize, MEM_RELEASE);
			this->GetSystemMessage("WriteProcessMemory");
			return 0;
		}

		if ((LoadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA")) == 0)
		{
			VirtualFreeEx(ProcessHandle, RemoteMemory, ModulePathSize, MEM_RELEASE);
			this->GetSystemMessage("LoadLibraryAddress");
			return 0;
		}

		char MutexName[64];

		wsprintf(MutexName, "MECANIKPROC%d", GetProcessId(ProcessHandle));

		HANDLE MutexHandle = CreateMutex(0, 0, MutexName);

		if (MutexHandle == 0)
		{
			VirtualFreeEx(ProcessHandle, RemoteMemory, ModulePathSize, MEM_RELEASE);
			this->GetSystemMessage("CreateMutex");
			return 0;
		}

		if ((RemoteThread = CreateRemoteThread(ProcessHandle, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryAddress, RemoteMemory, 0, 0)) == 0)
		{
			VirtualFreeEx(ProcessHandle, RemoteMemory, ModulePathSize, MEM_RELEASE);
			this->GetSystemMessage("CreateRemoteThread");
			CloseHandle(MutexHandle);
			return 0;
		}

		if (WaitForSingleObject(RemoteThread, INFINITE) != WAIT_OBJECT_0)
		{
			VirtualFreeEx(ProcessHandle, RemoteMemory, ModulePathSize, MEM_RELEASE);
			this->GetSystemMessage("WaitForSingleObject");
			CloseHandle(MutexHandle);
			return 0;
		}

		VirtualFreeEx(ProcessHandle, RemoteMemory, ModulePathSize, MEM_RELEASE);
		CloseHandle(MutexHandle);
		return 1;
	}


	void MecanikInjector::MProcessInjector::GetSystemMessage(char* Function)
	{
		LPVOID lpMsgBuf;

		LPVOID lpDisplayBuf;

		DWORD dw = GetLastError();

		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);

		lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)Function) + 100) * sizeof(TCHAR));

		StringCchPrintf((LPTSTR)lpDisplayBuf, LocalSize(lpDisplayBuf) / sizeof(TCHAR), TEXT("%s failed with error %d: %s (maybe x64 ?)"), Function, dw, lpMsgBuf);

		int iPosition = ListView_GetNextItem(hwndListLog, 0, LVNI_SELECTED);

		int pos = (int)SendMessage(hwndListLog, LB_ADDSTRING, iPosition, (LPARAM)lpDisplayBuf);
	}

	inline void MecanikInjector::MProcessInjector::InternalInit()
	{
		ManualMap::WDLL* NtDll;
		NtDll = new ManualMap::WDLL;

		if (!NtDll) {
			return;
		}

		if (!ManualMap::LoadFileFromMemory(GetCurrentProcess(), GetModuleHandleA("ntdll.dll"), 0, NtDll)) {
			return;
		}

		T_NtWaitForSingleObject = T_NtWaitForSingleObject ? T_NtWaitForSingleObject : reinterpret_cast<p_NtWaitForSingleObject>(ManualMap::GetProcAddressA(NtDll, "NtWaitForSingleObject"));
		T_NtCreateThreadEx = T_NtCreateThreadEx ? T_NtCreateThreadEx : reinterpret_cast<p_NtCreateThreadEx>(ManualMap::GetProcAddressA(NtDll, "NtCreateThreadEx"));
		T_RtlImageNtHeader = T_RtlImageNtHeader ? T_RtlImageNtHeader : reinterpret_cast<p_RtlImageNtHeader>(ManualMap::GetProcAddressA(NtDll, "RtlImageNtHeader"));
		T_NtOpenProcess = T_NtOpenProcess ? T_NtOpenProcess : reinterpret_cast<p_NtOpenProcess>(ManualMap::GetProcAddressA(NtDll, "NtOpenProcess"));
		T_NtWaitForAlertByThreadId = T_NtWaitForAlertByThreadId ? T_NtWaitForAlertByThreadId : reinterpret_cast<p_NtWaitForAlertByThreadId>(ManualMap::GetProcAddressA(NtDll, "NtWaitForAlertByThreadId"));
		T_NtWow64AllocateVirtualMemory64 = T_NtWow64AllocateVirtualMemory64 ? T_NtWow64AllocateVirtualMemory64 : reinterpret_cast<p_NtWow64AllocateVirtualMemory64>(ManualMap::GetProcAddressA(NtDll, "NtWow64AllocateVirtualMemory64"));
		T_NtWow64QueryInformationProcess64 = T_NtWow64QueryInformationProcess64 ? T_NtWow64QueryInformationProcess64 : reinterpret_cast<p_NtWow64QueryInformationProcess64>(ManualMap::GetProcAddressA(NtDll, "NtWow64QueryInformationProcess64"));
		T_NtWow64WriteVirtualMemory64 = T_NtWow64WriteVirtualMemory64 ? T_NtWow64WriteVirtualMemory64 : reinterpret_cast<p_NtWow64WriteVirtualMemory64>(ManualMap::GetProcAddressA(NtDll, "NtWow64WriteVirtualMemory64"));
		T_NtWow64ReadVirtualMemory64 = T_NtWow64ReadVirtualMemory64 ? T_NtWow64ReadVirtualMemory64 : reinterpret_cast<p_NtWow64ReadVirtualMemory64>(ManualMap::GetProcAddressA(NtDll, "NtWow64ReadVirtualMemory64"));
		T_NtWriteVirtualMemory = T_NtWriteVirtualMemory ? T_NtWriteVirtualMemory : reinterpret_cast<p_NtWriteVirtualMemory>(ManualMap::GetProcAddressA(NtDll, "NtWriteVirtualMemory"));
		T_NtProtectVirtualMemory = T_NtProtectVirtualMemory ? T_NtProtectVirtualMemory : reinterpret_cast<p_NtProtectVirtualMemory>(ManualMap::GetProcAddressA(NtDll, "NtProtectVirtualMemory"));
		T_NtReadVirtualMemory = T_NtReadVirtualMemory ? T_NtReadVirtualMemory : reinterpret_cast<p_NtReadVirtualMemory>(ManualMap::GetProcAddressA(NtDll, "NtReadVirtualMemory"));
	}

	std::string MecanikInjector::MProcessInjector::GetProcessName(DWORD aPid)
	{
		OBJECT_ATTRIBUTES ObjectAttributes;
		CLIENT_ID ClientId;
		InitializeObjectAttributes(&ObjectAttributes, 0, 0, 0, 0);
		ClientId.UniqueProcess = (PVOID)aPid;
		ClientId.UniqueThread = 0;
		HANDLE ProcessHandle = 0;
		NTSTATUS status;

		char ProcessName[MAX_PATH];
		wchar_t szProcessName[MAX_PATH];

		if (!NT_SUCCESS(status = T_NtOpenProcess(&ProcessHandle, GENERIC_READ, &ObjectAttributes, &ClientId))) {
			this->GetSystemMessage("NtOpenProcess");
			return 0;
		}

		if (ProcessHandle != 0)
		{
			if (GetProcessImageFileNameW(ProcessHandle, szProcessName, MAX_PATH) != 0)
			{
				wsprintf(ProcessName, "%S", ConvertModuleFileName(szProcessName));
				return ProcessName;
			}

			CloseHandle(ProcessHandle);
		}

		CloseHandle(ProcessHandle);
		return std::string();
	}
}