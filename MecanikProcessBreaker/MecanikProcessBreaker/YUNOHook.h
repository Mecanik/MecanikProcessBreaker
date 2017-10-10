#pragma once

// This file is part of YUNOHook
//
// Author: c5
// Thanks/Credits:  Kamshak, Spock, Kokole
//
// 2015



#include <Windows.h>
#include <utility>
#include <vector>
#include <TlHelp32.h>

// Each class handles 1 hook (except BP classes due to static handlers. Also bare in mind they are NOT THREAD SAFE and might cause some issues)
// YUNOHook handles all of your hooks
// I know it employs some bad coding practises eg. all classes being in one header and source file but its easily portable :)
// I also havent tested its functionality extensively as a whole. You might run into some issues, consider it your anti copypasta

namespace YUNO
{
	class YUNOHook;

	class CodeBP  // stripped for release
	{
	public:
		void Detach();
	};

	class PageBP
	{
	public:
		typedef void(*PageBP_Callback)(PCONTEXT pContext);
	private:
		static std::vector<std::pair<PageBP_Callback, void*>>m_Callbacks;
		static void* m_pLastUnhooked;
		static bool m_bAttachedHandler;
		static LONG CALLBACK ExceptionFilter(PEXCEPTION_POINTERS pException);
		static void* m_pExcHandler;

		void* m_pAddress; 
		DWORD m_dwOldProtection;	
	public:
		PageBP() { m_pAddress = 0; }

		static void AttachHandler();
		static void DetachHandler();

		bool IsHandlerAttached() { return m_bAttachedHandler; }
		void* GetHandler() { return m_pExcHandler; }
		void Attach(BYTE* pAddress, PageBP_Callback pHook);
		void Detach();
	};

	class HardwareBP
	{
	public:
		enum EHWBP_TYPE	{
			HWBP_TYPE_EXECUTE,
			HWBP_TYPE_WRITE,
			HWBP_TYPE_READWRITE
		};
		enum EHWBP_SIZE	{
			HWBP_SIZE_1,
			HWBP_SIZE_2,
			HWBP_SIZE_4,
			HWBP_SIZE_8
		};
		typedef void(*HWBP_Callback)(PCONTEXT pContext);
	private:
		static std::vector<std::pair<HWBP_Callback, void*>>m_Callbacks;
		static bool m_bAttachedHandler;
		static LONG CALLBACK ExceptionFilter(PEXCEPTION_POINTERS pException);
		static void* m_pExcHandler;

		bool AddHWBP(HANDLE hThread, EHWBP_TYPE type, EHWBP_SIZE size, void* ptr, PCONTEXT optionalContext);
		bool RemoveHWBP(HANDLE hThread, void* ptr, PCONTEXT optionalContext);

		std::vector<DWORD>m_ThreadsAttachedTo;
		void* m_pAddress;
	public:
		HardwareBP() { m_pAddress = 0; }

		static void AttachHandler();
		static void DetachHandler();

		bool IsHandlerAttached() { return m_bAttachedHandler; }
		void* GetHandler() { return m_pExcHandler; }

		bool Attach(DWORD dwThreadId, EHWBP_TYPE type, EHWBP_SIZE size, void* pAddress, PCONTEXT optionalContext, HWBP_Callback pHook);
		bool AttachAllThreads(EHWBP_TYPE type, EHWBP_SIZE size, void* pAddress, HWBP_Callback pHook);
		void Detach();
	};

	class CodeDetour  // stripped for release
	{
	public:
		void Detach();
	};

	class VMTHook
	{
	private:
		void* m_pOldVtable;
		void* m_pOriginalFunc;
		unsigned m_uFuncIndex;
		int m_iBitCount;

		bool m_bHooked;
	public:
		VMTHook() { m_bHooked = false; }

		// attach 32 bit vtable hook, returns old func pointer
		void* Attach32(PULONG ppVTable, PBYTE pHook, unsigned index, bool bFlushCache);
		// attach 64 bit vtable hook, returns old func pointer
		void* Attach64(PULONGLONG ppVTable, PBYTE pHook, unsigned index, bool bFlushCache);
		// detach the hook, restore old func pointer, do cleanup
		void Detach();
	};

	class IATHook
	{
	private:
		PIMAGE_DOS_HEADER m_pImage;
		PIMAGE_NT_HEADERS m_pNtHeaders;
		PIMAGE_IMPORT_DESCRIPTOR m_pImportDesc;
		PIMAGE_THUNK_DATA m_pThunk;
		PIMAGE_THUNK_DATA m_pOrigThunk;
		PIMAGE_IMPORT_BY_NAME m_pName;
		void* m_pOldPtr;
		void* m_pRegionBase;
		SIZE_T m_uRegionSize;

		bool m_bHooked;
	public:
		IATHook() { m_bHooked = false; }

		// attach hook, returns old func pointer
		void* Attach(HMODULE hModule, char* szModule, char* szProc, void *pHook);
		// detach the hook, restore old func pointer, do cleanup
		void Detach();
	};

	class YUNOHook
	{
	private:
		enum EReturnStatus {
			HOOK_FAILED = 0,
			HOOK_SUCCESS
		};

		std::vector<std::pair<CodeBP*, char*>>CodeBPHooks;
		std::vector<std::pair<PageBP*, char*>>PageBPHooks;
		std::vector<std::pair<HardwareBP*, char*>>HardwareBPHooks;
		std::vector<std::pair<CodeDetour*, char*>>CodeDetourHooks;
		std::vector<std::pair<VMTHook*, char*>>VMTHooks;
		std::vector<std::pair<IATHook*, char*>>IATHooks;

		char* CreateName(char* szHookName);
	public:
		YUNOHook();
		~YUNOHook();

		// szHookName is optional, used to track hooks by hook name, pass 0 if you dont want to track the hook
		// returns HOOK_FAILED if failed to hook
		// returns HOOK_SUCESS if successfully hooked

		EReturnStatus AddHWBP(char* szHookName, DWORD dwThreadId, HardwareBP::EHWBP_TYPE type, HardwareBP::EHWBP_SIZE size, void* pAddress, PCONTEXT optionalContext, HardwareBP::HWBP_Callback pHook);
		EReturnStatus AddHWBPAllThreads(char* szHookName, HardwareBP::EHWBP_TYPE type, HardwareBP::EHWBP_SIZE size, void* pAddress, HardwareBP::HWBP_Callback pHook);
		EReturnStatus AddPageBP(char* szHookName, BYTE* pAddress, PageBP::PageBP_Callback pHook);
		EReturnStatus AddIATHook(char* szHookName, HMODULE hModule, char* szModule, char* szProc, void* pHook);
		EReturnStatus AddVtableHook32(char* szHookName, PULONG ppVTable, PBYTE pHook, unsigned index, bool bFlushCache, PULONG pOriginalFunc /*for calling original func*/);
		EReturnStatus AddVtableHook64(char* szHookName, PULONGLONG ppVTable, PBYTE pHook, unsigned index, bool bFlushCache, PULONGLONG pOriginalFunc /*for calling original func*/);
		//

		// detach all hooks
		void DetachAll();
		// detach hook by hook name
		bool Detach(char* szName);
		// get hook by name
		template <typename hookType> hookType* GetHook(char* szName)
		{
			for (auto& i : CodeBPHooks)
			{
				if (!strcmp(szName, i.second))
					return (hookType*)i.first;
			}
			for (auto& i : PageBPHooks)
			{
				if (!strcmp(szName, i.second))
					return (hookType*)i.first;
			}
			for (auto& i : HardwareBPHooks)
			{
				if (!strcmp(szName, i.second))
					return (hookType*)i.first;
			}
			for (auto& i : CodeDetourHooks)
			{
				if (!strcmp(szName, i.second))
					return (hookType*)i.first;
			}
			for (auto& i : VMTHooks)
			{
				if (!strcmp(szName, i.second))
					return (hookType*)i.first;
			}
			for (auto& i : IATHooks)
			{
				if (!strcmp(szName, i.second))
					return (hookType*)i.first;
			}
			return 0;
		}
	};
}

