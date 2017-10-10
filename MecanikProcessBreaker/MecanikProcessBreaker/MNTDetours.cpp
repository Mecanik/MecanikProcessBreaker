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

#include "MNTDetours.h"
#include "X32_BEBIN.hpp"
#include "Utils.h"

namespace MecanikDetours
{

	MNTDetours T_MNTDetours;
	ManualMap::WDLL* NtDll;

	typedef NTSTATUS(NTAPI*p_NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
	typedef NTSTATUS(NTAPI*p_NtWaitForAlertByThreadId)(PVOID Address, PLARGE_INTEGER Timeout); 
    typedef NTSTATUS(NTAPI*p_NtWow64AllocateVirtualMemory64)(HANDLE ProcessHandle, PULONG64 BaseAddress, ULONG64 ZeroBits, PULONG64 Size, ULONG AllocationType, ULONG Protection);
	typedef NTSTATUS(NTAPI*p_NtWow64QueryInformationProcess64)(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID  ProcessInformation64, ULONG  Length, PULONG ReturnLength OPTIONAL);
	typedef NTSTATUS(NTAPI*p_NtWow64WriteVirtualMemory64)(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONGLONG BufferSize, PULONGLONG NumberOfBytesRead);
	typedef NTSTATUS(NTAPI*p_NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
	typedef NTSTATUS(NTAPI*p_NtWow64ReadVirtualMemory64)(HANDLE ProcessHandle, PVOID64 BaseAddress, PVOID Buffer, ULONGLONG BufferSize, PULONGLONG NumberOfBytesRead);
	typedef NTSTATUS(NTAPI*p_NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesRead);
	typedef NTSTATUS(NTAPI*p_NtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
	
	p_NtOpenProcess								T_NtOpenProcess;
	p_NtWaitForAlertByThreadId					T_NtWaitForAlertByThreadId;
	p_NtWow64AllocateVirtualMemory64			T_NtWow64AllocateVirtualMemory64;
	p_NtWow64QueryInformationProcess64			T_NtWow64QueryInformationProcess64;
	p_NtReadVirtualMemory						T_NtReadVirtualMemory;
	p_NtProtectVirtualMemory					T_NtProtectVirtualMemory;
	p_NtWow64WriteVirtualMemory64				T_NtWow64WriteVirtualMemory64;
	p_NtWriteVirtualMemory						T_NtWriteVirtualMemory;
	p_NtWow64ReadVirtualMemory64				T_NtWow64ReadVirtualMemory64;

	MNTDetours::MNTDetours()
	{
	}


	MNTDetours::~MNTDetours()
	{
	}

	VOID WINAPI MNTDetours::NTHook()
	{
		NtDll = new ManualMap::WDLL;

		if (!NtDll) {
			M_Console.ConsoleOutput(1, "[MNTDetours][FATAL] :: Failed to allocate memory for NtDll!");
			return;
		}

		if (!ManualMap::LoadFileFromMemory(GetCurrentProcess(), GetModuleHandleA("ntdll.dll"), 0, NtDll)) {
			M_Console.ConsoleOutput(1, "[MNTDetours][FATAL] :: [NtDll] LoadFileA failed!");
			return;
		}

		T_NtOpenProcess						= T_NtOpenProcess						? T_NtOpenProcess							: reinterpret_cast<p_NtOpenProcess>(ManualMap::GetProcAddressA(NtDll, "NtOpenProcess"));
		T_NtWaitForAlertByThreadId			= T_NtWaitForAlertByThreadId			? T_NtWaitForAlertByThreadId				: reinterpret_cast<p_NtWaitForAlertByThreadId>(ManualMap::GetProcAddressA(NtDll, "NtWaitForAlertByThreadId"));
		T_NtWow64AllocateVirtualMemory64	= T_NtWow64AllocateVirtualMemory64		? T_NtWow64AllocateVirtualMemory64			: reinterpret_cast<p_NtWow64AllocateVirtualMemory64>(ManualMap::GetProcAddressA(NtDll, "NtWow64AllocateVirtualMemory64"));
		T_NtWow64QueryInformationProcess64	= T_NtWow64QueryInformationProcess64	? T_NtWow64QueryInformationProcess64		: reinterpret_cast<p_NtWow64QueryInformationProcess64>(ManualMap::GetProcAddressA(NtDll, "NtWow64QueryInformationProcess64"));
		T_NtWow64WriteVirtualMemory64		= T_NtWow64WriteVirtualMemory64			? T_NtWow64WriteVirtualMemory64				: reinterpret_cast<p_NtWow64WriteVirtualMemory64>(ManualMap::GetProcAddressA(NtDll, "NtWow64WriteVirtualMemory64"));
		T_NtWow64ReadVirtualMemory64		= T_NtWow64ReadVirtualMemory64			? T_NtWow64ReadVirtualMemory64				: reinterpret_cast<p_NtWow64ReadVirtualMemory64>(ManualMap::GetProcAddressA(NtDll, "NtWow64ReadVirtualMemory64"));
		T_NtWriteVirtualMemory				= T_NtWriteVirtualMemory				? T_NtWriteVirtualMemory					: reinterpret_cast<p_NtWriteVirtualMemory>(ManualMap::GetProcAddressA(NtDll, "NtWriteVirtualMemory"));
		T_NtProtectVirtualMemory			= T_NtProtectVirtualMemory				? T_NtProtectVirtualMemory					: reinterpret_cast<p_NtProtectVirtualMemory>(ManualMap::GetProcAddressA(NtDll, "NtProtectVirtualMemory"));
		T_NtReadVirtualMemory				= T_NtReadVirtualMemory					? T_NtReadVirtualMemory						: reinterpret_cast<p_NtReadVirtualMemory>(ManualMap::GetProcAddressA(NtDll, "NtReadVirtualMemory"));

		if (!T_NtWaitForAlertByThreadId) {
			M_Console.ConsoleOutput(1, "[MNTDetours][WARNING] :: NtWaitForAlertByThreadId Function not found or cannot be imported!");
		} else {
			M_Console.ConsoleOutput(2, "[MNTDetours][SUCCESS] :: NtWaitForAlertByThreadId Function is imported!");
		}

		if (!T_NtWow64AllocateVirtualMemory64) {
			M_Console.ConsoleOutput(1, "[MNTDetours][WARNING] :: NtWow64AllocateVirtualMemory64 Function not found or cannot be imported!");
		} else {
			M_Console.ConsoleOutput(2, "[MNTDetours][SUCCESS] :: NtWow64AllocateVirtualMemory64 Function is imported!");
		}

		if (!T_NtWow64QueryInformationProcess64) {
			M_Console.ConsoleOutput(1, "[MNTDetours][WARNING] :: NtWow64QueryInformationProcess64 Function not found or cannot be imported!");
		} else {
			M_Console.ConsoleOutput(2, "[MNTDetours][SUCCESS] :: NtWow64QueryInformationProcess64 Function is imported!");
		}

		if (!T_NtWow64WriteVirtualMemory64) {
			M_Console.ConsoleOutput(1, "[MNTDetours][WARNING] :: NtWow64WriteVirtualMemory64 Function not found or cannot be imported!");
		} else {
			M_Console.ConsoleOutput(2, "[MNTDetours][SUCCESS] :: NtWow64WriteVirtualMemory64 Function is imported!");
		}

		if (!T_NtWow64ReadVirtualMemory64) {
			M_Console.ConsoleOutput(1, "[MNTDetours][WARNING] :: NtWow64ReadVirtualMemory64 Function not found or cannot be imported!");
		} else {
			M_Console.ConsoleOutput(2, "[MNTDetours][SUCCESS] :: NtWow64ReadVirtualMemory64 Function is imported!");
		}

		if (!T_NtWriteVirtualMemory) {
			M_Console.ConsoleOutput(1, "[MNTDetours][WARNING] :: NtWriteVirtualMemory Function not found or cannot be imported!");
		} else {
			M_Console.ConsoleOutput(2, "[MNTDetours][SUCCESS] :: NtWriteVirtualMemory Function is imported!");
		}

		if (!T_NtProtectVirtualMemory) {
			M_Console.ConsoleOutput(1, "[MNTDetours][WARNING] :: NtProtectVirtualMemory Function not found or cannot be imported!");
		} else {
			M_Console.ConsoleOutput(2, "[MNTDetours][SUCCESS] :: NtProtectVirtualMemory Function is imported!");
		}

		if (!T_NtReadVirtualMemory) {
			M_Console.ConsoleOutput(1, "[MNTDetours][WARNING] :: NtReadVirtualMemory Function not found or cannot be imported!");
		} else {
			M_Console.ConsoleOutput(2, "[MNTDetours][SUCCESS] :: NtReadVirtualMemory Function is imported!");
		}
	}

	DWORD MNTDetours::RIPFunction(LPCSTR lpModule, LPCSTR lpFuncName, LPVOID lpFunction, unsigned char *lpBackup)
	{
		BYTE jmp[6] = { 0xE9,0x00, 0x00, 0x00, 0x00 ,0xC3 };
		HANDLE ProcessHandle = GetCurrentProcess();
		DWORD Len = sizeof(jmp);
		DWORD OldProtect = NULL, NewOldProtect = NULL;
		NTSTATUS status;
		ULONG numBytesWritten = 0;

		char function[MAX_PATH] = {0};
		sprintf_s(function, "%s", lpFuncName);

		DWORD dwAddr	= (DWORD)GetProcedureAddress(GetModuleHandle(lpModule), (char *)lpFuncName);
		void* Address	= &dwAddr;

		if (!NT_SUCCESS(status=T_NtReadVirtualMemory(ProcessHandle, (LPVOID)dwAddr, lpBackup, 6, 0))) {
			this->GetSystemMessage("NtReadVirtualMemory");
			return 0;
		}
		
		#if(DEBUG == 1)
			M_Console.ConsoleOutput(4, "[%s][NtReadVirtualMemory] :: ADDR: 0x%08x - BCK: 0x%08x", function, (UINT)dwAddr, (UINT)lpBackup);
		#endif

		if (!NT_SUCCESS(status=T_NtProtectVirtualMemory(ProcessHandle, &Address, &Len, PAGE_EXECUTE_READWRITE, &OldProtect))) {
			this->GetSystemMessage("NtProtectVirtualMemory");
			VirtualFreeEx(ProcessHandle, Address, 0, MEM_RELEASE);
			return 0;
		}

		#if(DEBUG == 1)
			M_Console.ConsoleOutput(4, "[%s][NtProtectVirtualMemory] :: ADDR: 0x%08x - OldProtect:  0x%08x", function, (UINT)dwAddr, (UINT)OldProtect);
		#endif

		DWORD dwCalc = ((DWORD)lpFunction - dwAddr - 5);

		memcpy(&jmp[1], &dwCalc, 4);

		WriteProcessMemory(ProcessHandle, (LPVOID)dwAddr, jmp, 6, 0);

		//TODO Replace WriteProcessMemory with NtWriteVirtualMemory somehow...

		#if(DEBUG == 1)
			M_Console.ConsoleOutput(4, "[%s][NtWriteVirtualMemory] :: ADDR: 0x%08x - JMP: 0x%08x - WRT: 0x%08x", function, (UINT)dwAddr, (UINT)jmp, (UINT)numBytesWritten);
		#endif

		if (!NT_SUCCESS(status=T_NtProtectVirtualMemory(ProcessHandle, &Address, &Len, OldProtect, &OldProtect))) {
			this->GetSystemMessage("NtProtectVirtualMemory");
			VirtualFreeEx(ProcessHandle, Address, 0, MEM_RELEASE);
			return 0;
		}

		#if(DEBUG == 1)
			M_Console.ConsoleOutput(4, "[%s][NtProtectVirtualMemory] :: ADDR: 0x%08x - OldProtect: 0x%08x", function, (UINT)dwAddr, (UINT)OldProtect);
		#endif

		FlushInstructionCache(ProcessHandle, 0, 0);

		#if(DEBUG == 1)
			M_Console.ConsoleOutput(4, "[%s][FINISHED] :: ------------------------------------------------------------------------", function);
		#endif

		return dwAddr;
	}

	BOOL MNTDetours::UNRIPFunction(LPCSTR lpModule, LPCSTR lpFuncName, unsigned char *lpBackup)
	{
		NTSTATUS status;
		HANDLE ProcessHandle = GetCurrentProcess();
		DWORD dwAddr		 = (DWORD)GetProcedureAddress(GetModuleHandle(lpModule), (char *)lpFuncName);

		WriteProcessMemory(ProcessHandle, (LPVOID)dwAddr, lpBackup, 6, 0);
			
		//TODO Replace WriteProcessMemory with NtWriteVirtualMemory somehow...

		FlushInstructionCache(ProcessHandle, 0, 0);

		return TRUE;
	}

	/**
	\ Check if a function is already patched/detoured
	\ In some case, there will be some protection on functions so the process may terminate and our RIP will not work
	*/
	void MNTDetours::CheckIfPatched(const char* szDll, const char* szFunc)
	{
		M_Console.ConsoleOutput(6, "[MNTDetours][CheckIfPatched] :: Checking: %s, %s", szDll, szFunc);

		HMODULE hMod = GetModuleHandleA(szDll);

		if (!hMod)
		{
			M_Console.ConsoleOutput(1, "[MNTDetours][CheckIfPatched][ERROR] :: Cannot find module handle: %s", szDll);
			return;
		}

		BYTE* pFunc = (BYTE*)GetProcedureAddress(hMod, (char *)szFunc);

		if (!pFunc)
		{
			M_Console.ConsoleOutput(1, "[MNTDetours][CheckIfPatched][ERROR] :: Cannot get function pointer: %s, %s", szDll, szFunc);
			return;
		}

		if (pFunc[0] == 0xE9 || pFunc[0] == 0x90)
		{
			M_Console.ConsoleOutput(1, "[MNTDetours][CheckIfPatched][ERROR] :: Patch detected! %s, %s - 0x%08x", szDll, szFunc, (UINT)pFunc[0]);
		}
	}

	/**
	\ If there is a IAT hook present, this function will return us that address
	*/
	void MNTDetours::CheckForIATHook(const char* szDll, const char* szFunc)
	{
		M_Console.ConsoleOutput(6, "[MNTDetours][CheckForIATHook] :: Checking: %s, %s", szDll, szFunc);

		PVOID pfnOrigAddr	= GetProcAddress(GetModuleHandleA(szDll), szFunc);
		PVOID pfnIatAddr	= 0;

		if (!CPEUtil::GetFunctionPtrFromIAT(GetModuleHandle(0), szDll, szFunc, &pfnIatAddr))
		{
			this->GetSystemMessage("GetFunctionPtrFromIAT");
			return;
		}
		
		if (pfnOrigAddr != pfnIatAddr)
		{
			M_Console.ConsoleOutput(1, "[MNTDetours][CheckIfPatched][ERROR] :: IAT hook detected! %s, %s - IAT: 0x%08x - ORIG: 0x%08x", szDll, szFunc, (UINT)pfnOrigAddr, pfnIatAddr);
		}
	}

	/**
	\ Returns last error code formatted as a nice system message
	*/
	void MNTDetours::GetSystemMessage(char* Function)
	{
		LPVOID lpMsgBuf;

		LPVOID lpDisplayBuf;

		DWORD dw = GetLastError();

		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);

		lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)Function) + 100) * sizeof(TCHAR));

		StringCchPrintf((LPTSTR)lpDisplayBuf, LocalSize(lpDisplayBuf) / sizeof(TCHAR), TEXT("%s failed with error %d: %s"), Function, dw, lpMsgBuf);

		M_Console.ConsoleOutput(1, "[MNTDetours][ERROR] :: (%s)", lpDisplayBuf);
	}
}