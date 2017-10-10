#include "CMap.hpp"

namespace ManualMap
{
	BOOL LoadFileFromMemory(HANDLE hProcess, LPVOID lpDll, DWORD Flags, WDLL*& wFile)
	{
		PIMAGE_SECTION_HEADER SectionHeaders = 0;
		LPVOID lpwDll = 0, lpwThread = 0;
		HANDLE hThread = 0;
		BOOL Status = TRUE;
		DWORD_PTR Functions[7];
		SIZE_T Written = 0;
		ZeroMemory(Functions, 7);

		static auto xRtlCreateUserThread = [](HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN CreateSuspended, ULONG StackZeroBits, PULONG StackReserved, PULONG StackCommit, PVOID StartAddress, PVOID StartParameter, PHANDLE ThreadHandle, PVOID ClientID)->NTSTATUS
		{
			VIRTUALIZER_TIGER_BLACK_START
				static FARPROC Function = 0;
			NTSTATUS Result = -1;
			if (!Function)
			{
				Function = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");
				if (!Function)
					return -1;
				*reinterpret_cast<DWORD_PTR*>(&Function) ^= 0x7777;
			}
			VIRTUALIZER_TIGER_BLACK_END
				return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, PVOID)>(*reinterpret_cast<DWORD_PTR*>(&Function) ^ 0x7777)(ProcessHandle, SecurityDescriptor, CreateSuspended, StackZeroBits, StackReserved, StackCommit, StartAddress, StartParameter, ThreadHandle, ClientID);
		};

		auto xCreateRemoteThread = [](HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)->HANDLE
		{
			VIRTUALIZER_TIGER_BLACK_START
				ULONG Res = (dwStackSize == 0) ? 0x1000 : dwStackSize, Com = 0x1000;
			HANDLE ThreadHandle = 0;
			if (!xRtlCreateUserThread(hProcess, 0, (dwCreationFlags == CREATE_SUSPENDED) ? 1 : 0, 0, &Res, &Com, lpStartAddress, lpParameter, &ThreadHandle, 0))
				return ThreadHandle;
			VIRTUALIZER_TIGER_BLACK_END
				return 0;
		};

		if (!wFile)
		{
			SetLastError(1890);
			return 0;
		}
		wFile->Module = reinterpret_cast<HMODULE>(lpDll);
		if (!wFile->Module)
		{
			SetLastError(1790);
			return 0;
		}
		wFile->DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(wFile->Module);
		if (wFile->DosHeader &&
			wFile->DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			SetLastError(1792);
			return 0;
		}
		wFile->NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<DWORD_PTR>(wFile->Module) + wFile->DosHeader->e_lfanew));
		if (!wFile->NtHeader ||
			wFile->NtHeader->Signature != IMAGE_NT_SIGNATURE)
		{

			SetLastError(1793);
			return 0;
		}

		if (!(wFile->NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) &&
			!(wFile->NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
		{

			SetLastError(1794);
			return 0;
		}


#if defined _M_X64
		if (wFile->NtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 &&
			wFile->NtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_IA64)
		{

			SetLastError(1795);
			return 0;
		}
#elif defined _M_IX86
		if (wFile->NtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
		{

			SetLastError(1795);
			return 0;
		}
#endif
		VIRTUALIZER_TIGER_BLACK_START
			wFile->hProcess = hProcess;
		wFile->Flags = Flags;
		wFile->ImageSize = wFile->NtHeader->OptionalHeader.SizeOfImage;
		wFile->Image = (hProcess != GetCurrentProcess()) ? VirtualAllocEx(wFile->hProcess, 0, wFile->ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) : VirtualAlloc(0, wFile->ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!wFile->Image)
		{

			SetLastError(1796);
			return 0;
		}

		if ((hProcess != GetCurrentProcess()) ? !WriteProcessMemory(hProcess, wFile->Image, reinterpret_cast<PVOID>(wFile->Module), wFile->NtHeader->OptionalHeader.SizeOfHeaders, 0) : !memcpy(wFile->Image, wFile->Module, wFile->NtHeader->OptionalHeader.SizeOfHeaders))
		{
			VirtualFreeEx(wFile->hProcess, wFile->Image, wFile->ImageSize, MEM_DECOMMIT);

			SetLastError(2003);
			return 0;
		}

		wFile->Parameter = (wFile->hProcess != GetCurrentProcess()) ? VirtualAllocEx(wFile->hProcess, 0, sizeof(DWORD_PTR) * _countof(Functions), MEM_COMMIT, PAGE_EXECUTE_READWRITE) : VirtualAlloc(0, sizeof(DWORD_PTR) * _countof(Functions), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!wFile->Parameter)
		{
			VirtualFreeEx(wFile->hProcess, wFile->Image, wFile->ImageSize, MEM_DECOMMIT);

			SetLastError(8220);
			return 0;
		}
		Functions[6] = reinterpret_cast<DWORD_PTR>((lpDll == GetModuleHandleA("ntdll.dll") ? GetModuleHandleA("ntdll.dll") : (lpDll == GetModuleHandleA("kernel32.dll") ? GetModuleHandleA("kernel32.dll") : 0)));

		SectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(wFile->NtHeader + 1);
		for (int i = 0; i < wFile->NtHeader->FileHeader.NumberOfSections; i++)
		{
			if (hProcess == GetCurrentProcess())
			{
				memcpy(reinterpret_cast<PVOID>(reinterpret_cast<DWORD_PTR>(wFile->Image) + SectionHeaders[i].VirtualAddress), reinterpret_cast<PVOID>(reinterpret_cast<DWORD_PTR>(wFile->Module) + (Functions[6] ? SectionHeaders[i].VirtualAddress : SectionHeaders[i].PointerToRawData)), Functions[6] ? SectionHeaders[i].Misc.VirtualSize : SectionHeaders[i].SizeOfRawData);
				continue;
			}
			if (!WriteProcessMemory(hProcess, reinterpret_cast<PVOID>(reinterpret_cast<DWORD_PTR>(wFile->Image) + SectionHeaders[i].VirtualAddress), reinterpret_cast<PVOID>(reinterpret_cast<DWORD_PTR>(wFile->Module) + (Functions[6] ? SectionHeaders[i].VirtualAddress : SectionHeaders[i].PointerToRawData)), Functions[6] ? SectionHeaders[i].Misc.VirtualSize : SectionHeaders[i].SizeOfRawData, 0))
			{
				VirtualFreeEx(wFile->hProcess, wFile->Image, wFile->ImageSize, MEM_DECOMMIT);

				SetLastError(2003);
				return 0;
			}
		}


		wFile->Flags = Flags;
		Functions[0] = reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll"));
		Functions[1] = reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrGetProcedureAddress"));
		Functions[2] = reinterpret_cast<DWORD_PTR>(GetModuleHandleA("ntdll.dll"));
		Functions[3] = reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString"));
		Functions[4] = reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitAnsiString"));
		Functions[5] = reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAnsiStringToUnicodeString"));
		wFile->Entrypoint = reinterpret_cast<PVOID>((reinterpret_cast<DWORD_PTR>(wFile->Image) + wFile->NtHeader->OptionalHeader.AddressOfEntryPoint));
		wFile->BaseRelocation = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<DWORD_PTR>(wFile->Image) + wFile->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		wFile->ImportDes = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<DWORD_PTR>(wFile->Image) + wFile->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		wFile->Tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY>((reinterpret_cast<DWORD_PTR>(wFile->Image) + wFile->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress));
		wFile->NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<DWORD_PTR>(wFile->Image) + wFile->DosHeader->e_lfanew));
		if (!Functions[0] || !Functions[1] || !Functions[2] || !Functions[3] || !Functions[4] || !Functions[5] || !wFile->BaseRelocation || !wFile->ImportDes || !wFile->NtHeader)
		{
			VirtualFreeEx(wFile->hProcess, wFile->Image, wFile->ImageSize, MEM_DECOMMIT);
			VirtualFreeEx(wFile->hProcess, wFile->Parameter, sizeof(DWORD_PTR) * _countof(Functions), MEM_DECOMMIT);

			SetLastError(2010);
			return 0;
		}

		if ((wFile->hProcess != GetCurrentProcess()) ? !WriteProcessMemory(wFile->hProcess, wFile->Parameter, Functions, sizeof(DWORD_PTR) * _countof(Functions), 0) : !memcpy(wFile->Parameter, Functions, sizeof(DWORD_PTR) * _countof(Functions)))
		{
			VirtualFreeEx(wFile->hProcess, wFile->Image, wFile->ImageSize, MEM_DECOMMIT);
			VirtualFreeEx(wFile->hProcess, wFile->Parameter, sizeof(DWORD_PTR) * _countof(Functions), MEM_DECOMMIT);

			SetLastError(2010);
			return 0;
		}
		if (hProcess != GetCurrentProcess())
		{
			lpwDll = VirtualAllocEx(wFile->hProcess, 0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpwDll)
			{
				VirtualFreeEx(wFile->hProcess, wFile->Image, wFile->ImageSize, MEM_DECOMMIT);
				VirtualFreeEx(wFile->hProcess, wFile->Parameter, sizeof(DWORD_PTR) * _countof(Functions), MEM_DECOMMIT);

				SetLastError(2004);
				return 0;
			}

			if (!WriteProcessMemory(wFile->hProcess, lpwDll, wFile, 0x1000, &Written))
			{
				VirtualFreeEx(wFile->hProcess, wFile->Image, wFile->ImageSize, MEM_DECOMMIT);
				VirtualFreeEx(wFile->hProcess, wFile->Parameter, sizeof(DWORD_PTR) * _countof(Functions), MEM_DECOMMIT);
				VirtualFreeEx(wFile->hProcess, lpwDll, 0x1000, MEM_DECOMMIT);

				SetLastError(2005);
				return 0;
			}
			lpwThread = VirtualAllocEx(wFile->hProcess, 0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpwThread)
			{
				VirtualFreeEx(wFile->hProcess, wFile->Image, wFile->ImageSize, MEM_DECOMMIT);
				VirtualFreeEx(wFile->hProcess, wFile->Parameter, sizeof(DWORD_PTR) * _countof(Functions), MEM_DECOMMIT);
				VirtualFreeEx(wFile->hProcess, lpwDll, 0x1000, MEM_DECOMMIT);

				SetLastError(2006);
				return 0;
			}
			if (!WriteProcessMemory(wFile->hProcess, lpwThread, BuildFile, 0x1000, &Written))
			{
				VirtualFreeEx(wFile->hProcess, wFile->Image, wFile->ImageSize, MEM_DECOMMIT);
				VirtualFreeEx(wFile->hProcess, wFile->Parameter, sizeof(DWORD_PTR) * _countof(Functions), MEM_DECOMMIT);
				VirtualFreeEx(wFile->hProcess, lpwDll, 0x1000, MEM_DECOMMIT);
				VirtualFreeEx(wFile->hProcess, lpwThread, 0x1000, MEM_DECOMMIT);

				SetLastError(2007);
				return 0;
			}
			hThread = xCreateRemoteThread(wFile->hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpwThread), lpwDll, 0, 0);
			if (!hThread)
			{
				VirtualFreeEx(wFile->hProcess, wFile->Image, wFile->ImageSize, MEM_DECOMMIT);
				VirtualFreeEx(wFile->hProcess, wFile->Parameter, sizeof(DWORD_PTR) * _countof(Functions), MEM_DECOMMIT);
				VirtualFreeEx(wFile->hProcess, lpwDll, 0x1000, MEM_DECOMMIT);
				VirtualFreeEx(wFile->hProcess, lpwThread, 0x1000, MEM_DECOMMIT);

				SetLastError(2008);
				return 0;
			}
			WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
			if (!VirtualFreeEx(wFile->hProcess, lpwDll, 0x1000, MEM_DECOMMIT) ||
				!VirtualFreeEx(wFile->hProcess, lpwThread, 0x1000, MEM_DECOMMIT))
			{

				SetLastError(2009);
				return 0;
			}
			return 1;
		}
		Status = BuildFile(wFile) ? true : false;
		VIRTUALIZER_TIGER_BLACK_END
			return Status;
	}
	FARPROC GetProcAddressA(WDLL* wDll, LPCSTR lpName)
	{
		VIRTUALIZER_TIGER_BLACK_START
			LPWSTR wName = 0;
		INT NameSize = 0;
		FARPROC Function = 0;
		NameSize = MultiByteToWideChar(CP_UTF8, 0, lpName, -1, NULL, 0);
		if (!NameSize)
		{
			SetLastError(4031);
			return FALSE;
		}
		wName = new wchar_t[NameSize];
		if (!wName)
		{
			SetLastError(4032);
			return FALSE;
		}
		if (!MultiByteToWideChar(CP_UTF8, 0, lpName, -1, wName, NameSize))
		{
			SetLastError(4033);
			if (wName) delete wName;
			return FALSE;
		}
		Function = GetProcAddressW(wDll, wName);
		if (wName) delete wName;
		VIRTUALIZER_TIGER_BLACK_END
			return Function;
	}
	FARPROC GetProcAddressW(WDLL* wDll, LPCWSTR lpName)
	{
		VIRTUALIZER_TIGER_BLACK_START
			DWORD Oridinal = reinterpret_cast<DWORD>(lpName), OrdSize = 0;
		size_t lpNameSize = 0;
		LPSTR lpOrdName = "";
		PIMAGE_EXPORT_DIRECTORY ImageDirectory = 0;
		PIMAGE_NT_HEADERS64 Nt64Header = 0;
		if (!wDll || !lpName)
		{
			SetLastError(4001);
			return FALSE;
		}
		if (!wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress ||
			!wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
		{
			SetLastError(4002);
			return FALSE;
		}
		switch (wDll->NtHeader->OptionalHeader.Magic)
		{
		case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			ImageDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<DWORD_PTR>(wDll->Image) + wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			break;
		case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			ImageDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<DWORD_PTR>(wDll->Image) + wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			break;
		default:
			SetLastError(3999);
			return FALSE;
			break;
		}

		if (!ImageDirectory)
		{
			SetLastError(4003);
			return FALSE;
		}

		if (Oridinal < 0x10000)
		{
			if (Oridinal < ImageDirectory->Base)
			{
				SetLastError(4004);
				return FALSE;
			}
			Oridinal -= ImageDirectory->Base;
		}

		if ((lpNameSize = wcslen(lpName)))
		{
			OrdSize = WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, lpName, -1, 0, 0, 0, 0);
			if (!OrdSize)
			{
				SetLastError(4005);
				return FALSE;
			}
			lpOrdName = new char[OrdSize];
			if (!lpOrdName)
			{
				SetLastError(4006);
				return FALSE;
			}
			if (!WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, lpName, -1, lpOrdName, OrdSize, 0, 0))
			{
				SetLastError(4007);
				if (lpOrdName) delete lpOrdName;
				return FALSE;
			}
			for (int i = 0; i < ImageDirectory->NumberOfNames; ++i)
			{
				if (!_stricmp(reinterpret_cast<char*>(((reinterpret_cast<DWORD*>(ImageDirectory->AddressOfNames + reinterpret_cast<DWORD_PTR>(wDll->Image)))[i] + reinterpret_cast<DWORD_PTR>(wDll->Image))), lpOrdName))
				{
					Oridinal = reinterpret_cast<WORD*>((ImageDirectory->AddressOfNameOrdinals + reinterpret_cast<DWORD_PTR>(wDll->Image)))[i];
					break;
				}
			}
		}

		if (Oridinal >= ImageDirectory->NumberOfFunctions)
		{
			SetLastError(4000);
			if (lpOrdName) delete lpOrdName;
			return FALSE;
		}
		VIRTUALIZER_TIGER_BLACK_END
			return reinterpret_cast<FARPROC>((reinterpret_cast<DWORD*>((ImageDirectory->AddressOfFunctions + reinterpret_cast<DWORD_PTR>(wDll->Image)))[Oridinal] + reinterpret_cast<DWORD_PTR>(wDll->Image)));
	}
	BOOL BuildFile(WDLL* wDll)
	{
		typedef struct _STRING {
			USHORT Length;
			USHORT MaximumLength;
			PCHAR  Buffer;
		} ANSI_STRING, *PANSI_STRING;
		typedef struct _LSA_UNICODE_STRING {
			USHORT Length;
			USHORT MaximumLength;
			PWSTR  Buffer;
		} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

		PIMAGE_DOS_HEADER DosHeader = 0;
		PIMAGE_NT_HEADERS NtHeader = 0;
		PIMAGE_BASE_RELOCATION BaseRelocationStart = 0, BaseRelocationEnd = 0, xBaseRelocationStart = 0, xBaseRelocationEnd = 0;
		PIMAGE_IMPORT_DESCRIPTOR ImportDes = 0;
		PIMAGE_IMPORT_BY_NAME ImportName = 0;
		PIMAGE_TLS_CALLBACK* TlsCallBack = 0;
		PIMAGE_EXPORT_DIRECTORY Exports = 0;
		PIMAGE_THUNK_DATA FirstThunk = 0, OriginalThunk = 0;
		DWORD_PTR Delta = 0,
			*PTR = 0, Count = 0, Counter = 0, Function = 0, *Functions = 0, EntryPoint = 0, Oridinal = 0;
		WORD* List = 0;
		char lpNtDll[] = { 0x6e,  0x74, 0x64, 0x6c, 0x6c };

		HMODULE Module = 0, NtDll = 0;
		BOOL Status = TRUE;
		UNICODE_STRING DllName;
		ANSI_STRING FunctionName;

		if (!wDll)
			return FALSE;

		Delta = (reinterpret_cast<DWORD_PTR>(wDll->Image) - wDll->NtHeader->OptionalHeader.ImageBase);
		BaseRelocationStart = wDll->BaseRelocation;
		ImportDes = wDll->ImportDes;
		Functions = reinterpret_cast<DWORD_PTR*>(wDll->Parameter);

		if (!Delta || !BaseRelocationStart || !ImportDes || !Functions)
			return FALSE;

		if (Functions[6])
		{
			DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Functions[2]);
			if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
				return FALSE;
			NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(Functions[2] + DosHeader->e_lfanew);
			if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
				return FALSE;
		}
		while (true)
		{
			if (*reinterpret_cast<BYTE*>(Functions[2]) == 0x4D &&
				*reinterpret_cast<BYTE*>(Functions[2] + 1) == 0x5A &&
				*reinterpret_cast<BYTE*>(Functions[2] + 2) == 0x90)
				break;
		}


		if (wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress &&
			wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			BaseRelocationStart = reinterpret_cast<PIMAGE_BASE_RELOCATION>((reinterpret_cast<DWORD_PTR>(wDll->Image) + wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
			BaseRelocationEnd = reinterpret_cast<PIMAGE_BASE_RELOCATION>((reinterpret_cast<DWORD_PTR>(BaseRelocationStart) + wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size - sizeof(IMAGE_BASE_RELOCATION)));
			if (Functions[6])
			{
				xBaseRelocationStart = reinterpret_cast<PIMAGE_BASE_RELOCATION>((Functions[2] + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
				xBaseRelocationEnd = reinterpret_cast<PIMAGE_BASE_RELOCATION>((reinterpret_cast<DWORD_PTR>(BaseRelocationStart) + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size - sizeof(IMAGE_BASE_RELOCATION)));
			}
			for (; BaseRelocationStart->VirtualAddress; BaseRelocationStart = reinterpret_cast<PIMAGE_BASE_RELOCATION>((reinterpret_cast<LPBYTE>(BaseRelocationStart) + BaseRelocationStart->SizeOfBlock)))
			{
				if (BaseRelocationStart->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
				{
					Count = (BaseRelocationStart->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
					List = reinterpret_cast<PWORD>(BaseRelocationStart + 1);

					for (Counter = 0; Counter < Count; Counter++)
					{
						if ((List[Counter]))
							*reinterpret_cast<DWORD_PTR*>((reinterpret_cast<LPBYTE>(wDll->Image) + (BaseRelocationStart->VirtualAddress + (List[Counter] & 0xFFF)))) = Functions[6] ? *reinterpret_cast<DWORD_PTR*>((reinterpret_cast<LPBYTE>(Functions[2]) + (xBaseRelocationStart->VirtualAddress + (List[Counter] & 0xFFF)))) : *reinterpret_cast<DWORD_PTR*>((reinterpret_cast<LPBYTE>(wDll->Image) + (BaseRelocationStart->VirtualAddress + (List[Counter] & 0xFFF)))) + Delta;
					}
				}
				if (Functions[6])
					xBaseRelocationStart = reinterpret_cast<PIMAGE_BASE_RELOCATION>((reinterpret_cast<LPBYTE>(xBaseRelocationStart) + xBaseRelocationStart->SizeOfBlock));
			}
		}

		if (wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress &&
			wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			for (; ImportDes->Characteristics; ImportDes++)
			{
				OriginalThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD_PTR>(wDll->Image) + ImportDes->OriginalFirstThunk);
				FirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(reinterpret_cast<DWORD_PTR>(wDll->Image) + ImportDes->FirstThunk);

				Module = 0;
				reinterpret_cast<VOID(NTAPI*)(PANSI_STRING, LPCSTR)>(Functions[3])(&FunctionName, reinterpret_cast<LPCSTR>(reinterpret_cast<DWORD_PTR>(wDll->Image) + ImportDes->Name));
				if (reinterpret_cast<NTSTATUS(NTAPI*)(PUNICODE_STRING, PANSI_STRING, BOOLEAN)>(Functions[5])(&DllName, &FunctionName, true) != 0)
					return FALSE;
				if (reinterpret_cast<NTSTATUS(NTAPI*)(PWCHAR, ULONG, PUNICODE_STRING, HMODULE*)>(Functions[0])(0, 0, &DllName, &Module) != 0)
					return FALSE;
				if (!Module)
					return FALSE;

				while (OriginalThunk->u1.AddressOfData)
				{
					if (OriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					{
						if (reinterpret_cast<NTSTATUS(WINAPI*)(HMODULE, PANSI_STRING, WORD, DWORD_PTR*)>(Functions[1])(Module, 0, OriginalThunk->u1.Ordinal & 0xFFFF, &Function) != 0)
							return FALSE;
						FirstThunk->u1.Function = Function;
						OriginalThunk++;
						FirstThunk++;
						continue;
					}
					ImportName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(((reinterpret_cast<DWORD_PTR>(wDll->Image) + OriginalThunk->u1.AddressOfData)));
					reinterpret_cast<VOID(NTAPI*)(PANSI_STRING, LPCSTR)>(Functions[3])(&FunctionName, reinterpret_cast<LPCSTR>(ImportName->Name));
					if (reinterpret_cast<NTSTATUS(WINAPI*)(HMODULE, PANSI_STRING, WORD, DWORD_PTR*)> (Functions[1])(Module, &FunctionName, 0, &Function) != 0)
						return FALSE;
					FirstThunk->u1.Function = Function;
					OriginalThunk++;
					FirstThunk++;
				}
			}

		}

		if (wDll->Tls &&
			wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
		{
			TlsCallBack = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(wDll->Tls->AddressOfCallBacks);
			if (TlsCallBack)
			{
				while (*TlsCallBack)
				{
					if ((wDll->NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
						Status = reinterpret_cast<BOOL(WINAPI*)(DWORD_PTR, DWORD, LPVOID)>(*TlsCallBack)(reinterpret_cast<DWORD_PTR>(wDll->Image), DLL_PROCESS_ATTACH, NULL);
					if ((wDll->NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == IMAGE_FILE_EXECUTABLE_IMAGE)
						Status = reinterpret_cast<INT(*)()>(wDll->Entrypoint)();
					TlsCallBack++;
				}
			}
		}

		if (wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
			wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size &&
			(wDll->Flags & ManualMap_FLAGS::CALL_EXPORT) == ManualMap_FLAGS::CALL_EXPORT)
		{
			Exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<DWORD_PTR>(wDll->Image) + wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			Oridinal = 0;
			if (Oridinal + 1 > Exports->NumberOfFunctions)
				return FALSE;
			wDll->Entrypoint = reinterpret_cast<FARPROC>((reinterpret_cast<DWORD*>((Exports->AddressOfFunctions + reinterpret_cast<DWORD_PTR>(wDll->Image)))[Oridinal] + reinterpret_cast<DWORD_PTR>(wDll->Image)));
			if (wDll->Entrypoint)
			{
				Status = reinterpret_cast<BOOL(WINAPI*)(DWORD_PTR, DWORD, LPVOID)>(wDll->Entrypoint)(reinterpret_cast<DWORD_PTR>(wDll->Image), DLL_PROCESS_ATTACH, NULL);
			}
		}

		if (wDll->NtHeader->OptionalHeader.AddressOfEntryPoint &&
			!(wDll->Flags & ManualMap_FLAGS::CALL_NO_ENTRYPOINT))
		{
			if (wDll->Entrypoint)
			{
				if ((wDll->NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
					Status = reinterpret_cast<BOOL(WINAPI*)(DWORD_PTR, DWORD, LPVOID)>(wDll->Entrypoint)(reinterpret_cast<DWORD_PTR>(wDll->Image), DLL_PROCESS_ATTACH, NULL);
				if ((wDll->NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == IMAGE_FILE_EXECUTABLE_IMAGE)
					Status = reinterpret_cast<INT(*)()>(wDll->Entrypoint)();
			}
		}

		if ((wDll->Flags & ManualMap_FLAGS::HIDE_PE) && NtDll)
		{
			for (int i = 0;i < 0x1000;i++)
				reinterpret_cast<BYTE*>(wDll->Image)[i] = reinterpret_cast<BYTE*>(NtDll)[i];
		}
		return Status;
	};
	BOOL UnloadFile(WDLL* wDll)
	{
		VIRTUALIZER_TIGER_BLACK_START
			BOOL Result = TRUE;
		LPVOID lpUnloadThread = 0, lpwDll = 0;
		HANDLE hThread = 0;
		typedef DWORD(WINAPI*pThreadDef)(WDLL* wDll);
		pThreadDef eThreadDef = 0;

		static auto xRtlCreateUserThread = [](HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN CreateSuspended, ULONG StackZeroBits, PULONG StackReserved, PULONG StackCommit, PVOID StartAddress, PVOID StartParameter, PHANDLE ThreadHandle, PVOID ClientID)->NTSTATUS
		{
			VIRTUALIZER_TIGER_BLACK_START
				static FARPROC Function = 0;
			NTSTATUS Result = -1;
			if (!Function)
			{
				Function = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCreateUserThread");
				if (!Function)
					return -1;
				*reinterpret_cast<DWORD_PTR*>(&Function) ^= 0x7777;
			}
			VIRTUALIZER_TIGER_BLACK_END
				return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, PVOID)>(*reinterpret_cast<DWORD_PTR*>(&Function) ^ 0x7777)(ProcessHandle, SecurityDescriptor, CreateSuspended, StackZeroBits, StackReserved, StackCommit, StartAddress, StartParameter, ThreadHandle, ClientID);
		};

		auto xCreateRemoteThread = [](HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)->HANDLE
		{
			VIRTUALIZER_TIGER_BLACK_START
				ULONG Res = (dwStackSize == 0) ? 0x1000 : dwStackSize, Com = 0x1000;
			HANDLE ThreadHandle = 0;
			if (!xRtlCreateUserThread(hProcess, 0, (dwCreationFlags == CREATE_SUSPENDED) ? 1 : 0, 0, &Res, &Com, lpStartAddress, lpParameter, &ThreadHandle, 0))
				return ThreadHandle;
			VIRTUALIZER_TIGER_BLACK_END
				return 0;
		};

		if (!(wDll->Flags & ManualMap_FLAGS::CALL_NO_ENTRYPOINT))
		{
			if (wDll->Entrypoint)
			{
				lpwDll = VirtualAllocEx(wDll->hProcess, 0, 0x100, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (!lpwDll)
				{
					SetLastError(3000);
					Result = FALSE;
				}
				if (!WriteProcessMemory(wDll->hProcess, lpwDll, wDll, 0x100, 0))
				{
					SetLastError(3000);
					Result = FALSE;
				}
				lpUnloadThread = VirtualAllocEx(wDll->hProcess, 0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				if (!lpUnloadThread)
				{
					SetLastError(3000);
					Result = FALSE;
				}
				static auto Thread = [](WDLL* wDll)->DWORD
				{
					PIMAGE_EXPORT_DIRECTORY Exports = 0;
					PIMAGE_TLS_CALLBACK* TlsCallBack;
					DWORD Oridinal = 0, Status = 0;
					if (wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
						wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size &&
						(wDll->Flags & ManualMap_FLAGS::CALL_EXPORT))
					{
						Exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<DWORD_PTR>(wDll->Image) + wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
						Oridinal = 0;
						if (Oridinal > Exports->NumberOfFunctions)
							return FALSE;
						wDll->Entrypoint = reinterpret_cast<FARPROC>((reinterpret_cast<DWORD*>((Exports->AddressOfFunctions + reinterpret_cast<DWORD_PTR>(wDll->Image)))[Oridinal] + reinterpret_cast<DWORD_PTR>(wDll->Image)));
						if (wDll->Entrypoint)
						{
							Status = reinterpret_cast<BOOL(WINAPI*)(DWORD_PTR, DWORD, LPVOID)>(wDll->Entrypoint)(reinterpret_cast<DWORD_PTR>(wDll->Image), DLL_PROCESS_DETACH, NULL);
						}
					}
					if (wDll->Tls &&
						wDll->NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
					{
						TlsCallBack = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(wDll->Tls->AddressOfCallBacks);
						if (TlsCallBack)
						{
							while (*TlsCallBack)
							{
								if ((wDll->NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
									Status = reinterpret_cast<BOOL(WINAPI*)(DWORD_PTR, DWORD, LPVOID)>(*TlsCallBack)(reinterpret_cast<DWORD_PTR>(wDll->Image), DLL_PROCESS_DETACH, NULL);
								if ((wDll->NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == IMAGE_FILE_EXECUTABLE_IMAGE)
									Status = reinterpret_cast<INT(*)()>(*TlsCallBack)();
								TlsCallBack++;
							}
						}
					}

					wDll->Entrypoint = reinterpret_cast<PVOID>((reinterpret_cast<DWORD_PTR>(wDll->Image) + wDll->NtHeader->OptionalHeader.AddressOfEntryPoint));
					if (wDll->NtHeader->OptionalHeader.AddressOfEntryPoint && !(ManualMap_FLAGS::CALL_EXPORT))
					{
						if ((wDll->NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL)
							Status = reinterpret_cast<BOOL(WINAPI*)(DWORD_PTR, DWORD, LPVOID)>(wDll->Entrypoint)(reinterpret_cast<DWORD_PTR>(wDll->Image), DLL_PROCESS_ATTACH, NULL);
						if ((wDll->NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == IMAGE_FILE_EXECUTABLE_IMAGE)
							Status = reinterpret_cast<INT(*)()>(wDll->Entrypoint)();
					}
					return Status;
				};
				if (!WriteProcessMemory(wDll->hProcess, lpUnloadThread, static_cast<LPCVOID>(*reinterpret_cast<LPCVOID*>(&Thread)), 0x100, 0))
				{
					SetLastError(3000);
					Result = FALSE;
				}
				hThread = xCreateRemoteThread(wDll->hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpUnloadThread), lpwDll, 0, 0);
				if (!hThread)
				{
					SetLastError(3000);
					Result = FALSE;
				}
				if (hThread)
					WaitForSingleObject(hThread, INFINITE);
				if (lpUnloadThread &&
					!VirtualFreeEx(wDll->hProcess, lpUnloadThread, 0x100, MEM_DECOMMIT) ||
					lpwDll &&
					!VirtualFreeEx(wDll->hProcess, lpwDll, 0x100, MEM_DECOMMIT))
				{
					SetLastError(3000);
					Result = FALSE;
				}
			}
		}
		if (wDll->Image)
		{
			if (!VirtualFreeEx(wDll->hProcess, wDll->Image, wDll->ImageSize, MEM_DECOMMIT))
			{
				SetLastError(3002);
				return FALSE;
			}
		}
		VIRTUALIZER_TIGER_BLACK_END
			return Result;
	}
}