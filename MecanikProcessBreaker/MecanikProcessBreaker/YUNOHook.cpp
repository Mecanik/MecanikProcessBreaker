#include "stdafx.h"
#include "YUNOHook.h"

// This file is part of YUNOHook
//
// Author: c5
// Thanks/Credits:  Kamshak, Spock, Kokole
//
// 2015


using namespace YUNO;

// ======== INT3 BP ========

void CodeBP::Detach()
{

}

// ======== PAGE BP ========

std::vector<std::pair<PageBP::PageBP_Callback, void*>> PageBP::m_Callbacks;
void* PageBP::m_pLastUnhooked = 0;
bool PageBP::m_bAttachedHandler = false;
void* PageBP::m_pExcHandler = 0;
void PageBP::Detach()
{
	for (size_t i = 0; i < m_Callbacks.size(); i++)
	{
		if (m_Callbacks[i].second == m_pAddress)
		{
			DWORD oldProt;
			VirtualProtect((LPVOID)m_pAddress, 1, m_dwOldProtection, &oldProt);
			m_Callbacks.erase(m_Callbacks.begin() + i);
		}
	}
}

void PageBP::DetachHandler()
{
	if (!m_bAttachedHandler)
		return;

	RemoveVectoredExceptionHandler(m_pExcHandler);
	m_bAttachedHandler = false;
}

void PageBP::AttachHandler()
{
	if (m_bAttachedHandler)
		return;

	m_pExcHandler = AddVectoredExceptionHandler(1, PageBP::ExceptionFilter);
	m_bAttachedHandler = true;
}

void PageBP::Attach(BYTE* pAddress, PageBP_Callback pHook)
{
	m_Callbacks.push_back(std::make_pair(pHook, pAddress));

	m_pAddress = pAddress;
	VirtualProtect((LPVOID)pAddress, 1, PAGE_NOACCESS, &m_dwOldProtection);
}

LONG CALLBACK PageBP::ExceptionFilter(PEXCEPTION_POINTERS pException)
{
	DWORD oldProt;

	if (pException->ExceptionRecord->ExceptionCode != STATUS_ACCESS_VIOLATION && pException->ExceptionRecord->ExceptionCode != STATUS_SINGLE_STEP)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}

	if (pException->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		if (m_pLastUnhooked)
			VirtualProtect((LPVOID)m_pLastUnhooked, 1, PAGE_NOACCESS, &oldProt);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	for (auto& i : m_Callbacks)
	{
#if _WIN64
		if (i.second == (void*)pException->ContextRecord->Rip)
		{
			i.first(pException->ContextRecord);
		}
#else
		if (i.second == (void*)pException->ContextRecord->Eip)
		{
			i.first(pException->ContextRecord);
		}
#endif
	}

#if _WIN64
	m_pLastUnhooked = (void*)pException->ContextRecord->Rip;
	VirtualProtect((LPVOID)pException->ContextRecord->Rip, 1, PAGE_EXECUTE, &oldProt);
#else
	m_pLastUnhooked = (void*)pException->ContextRecord->Eip;
	VirtualProtect((LPVOID)pException->ContextRecord->Eip, 1, PAGE_EXECUTE, &oldProt);
#endif
	pException->ContextRecord->EFlags |= 0x100;
	return EXCEPTION_CONTINUE_EXECUTION;
}

// ======== HW BP ========

std::vector<std::pair<HardwareBP::HWBP_Callback, void*>> HardwareBP::m_Callbacks;
bool HardwareBP::m_bAttachedHandler = false;
void* HardwareBP::m_pExcHandler = 0;

void HardwareBP::Detach()
{
	for (auto& t : m_ThreadsAttachedTo)
	{
		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, t);
		if (hThread)
		{
			if (SuspendThread(hThread) != (DWORD)-1)
			{
				RemoveHWBP(hThread, m_pAddress, NULL);
				ResumeThread(hThread);
				CloseHandle(hThread);
			}
		}
	}
	m_ThreadsAttachedTo.clear();
}

void HardwareBP::DetachHandler()
{
	if (!m_bAttachedHandler)
		return;

	RemoveVectoredExceptionHandler(m_pExcHandler);
	m_bAttachedHandler = false;
}

void HardwareBP::AttachHandler()
{
	if (m_bAttachedHandler)
		return;

	m_pExcHandler = AddVectoredExceptionHandler(1, HardwareBP::ExceptionFilter);
	m_bAttachedHandler = true;
}

bool HardwareBP::Attach(DWORD dwThreadId, HardwareBP::EHWBP_TYPE type, HardwareBP::EHWBP_SIZE size, void* pAddress, PCONTEXT optionalContext, HardwareBP::HWBP_Callback pHook)
{
	bool attached = false;

	m_pAddress = pAddress;
	m_Callbacks.push_back(std::make_pair(pHook, pAddress));

	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, dwThreadId);
	if (hThread)
	{
		if (SuspendThread(hThread) != (DWORD)-1)
		{
			attached = AddHWBP(hThread, type, size, pAddress, optionalContext);
			if (attached)
				m_ThreadsAttachedTo.push_back(dwThreadId);
			ResumeThread(hThread);
			CloseHandle(hThread);
		}
	}

	if (!attached)
		m_Callbacks.pop_back();

	return attached;
}

bool HardwareBP::AttachAllThreads(HardwareBP::EHWBP_TYPE type, HardwareBP::EHWBP_SIZE size, void* pAddress, HardwareBP::HWBP_Callback pHook)
{
	HANDLE hThreadSnap;
	THREADENTRY32 te32;
	HANDLE hThread;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return false;

	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);
		return false;
	}

	m_Callbacks.push_back(std::make_pair(pHook, pAddress));
	m_pAddress = pAddress;

	do
	{
		// dont put hwbp for our thread
		if (te32.th32OwnerProcessID == GetCurrentProcessId() &&
			te32.th32ThreadID != GetCurrentThreadId())
		{
			hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
			if (hThread)
			{
				if (SuspendThread(hThread) != (DWORD)-1)
				{
					if (AddHWBP(hThread, type, size, pAddress, NULL))
						m_ThreadsAttachedTo.push_back(te32.th32ThreadID);
					ResumeThread(hThread);
					CloseHandle(hThread);
				}
			}
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);

	return true;
}

LONG CALLBACK HardwareBP::ExceptionFilter(PEXCEPTION_POINTERS pException)
{
	for (auto& i : m_Callbacks)
	{
		if (pException->ExceptionRecord->ExceptionAddress == i.second)
		{
			i.first(pException->ContextRecord);
			
			// set RF (resume flag)
			pException->ContextRecord->EFlags |= (1 << 16);

			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

bool HardwareBP::AddHWBP(HANDLE hThread, HardwareBP::EHWBP_TYPE type, HardwareBP::EHWBP_SIZE size, void* ptr, PCONTEXT optionalContext)
{
	CONTEXT context;
	if (!optionalContext)
	{
		memset(&context, 0, sizeof(CONTEXT));
		context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (!GetThreadContext(hThread, &context))
			return false;
	}
	else
		context = *optionalContext;

	// find a free debug register
	int dbgIndex;
	if (!(context.Dr7 & (1 << 0)))
		dbgIndex = 0;
	else if (!(context.Dr7 & (1 << 2)))
		dbgIndex = 1;
	else if (!(context.Dr7 & (1 << 4)))
		dbgIndex = 2;
	else if (!(context.Dr7 & (1 << 6)))
		dbgIndex = 3;
	else
		return false;

	// set hwbp type
	if (type == HWBP_TYPE_EXECUTE)
		context.Dr7 |= (0 << (16 + dbgIndex * 2));
	else if (type == HWBP_TYPE_WRITE)
		context.Dr7 |= (1 << (16 + dbgIndex * 2));
	else if (type == HWBP_TYPE_READWRITE)
		context.Dr7 |= (3 << (16 + dbgIndex * 2));
	else
		return false;

	// set hwbp size
	if (size == HWBP_SIZE_1)
		context.Dr7 |= (0 << (24 + dbgIndex * 2));
	else if (size == HWBP_SIZE_2)
		context.Dr7 |= (1 << (24 + dbgIndex * 2));
	else if (size == HWBP_SIZE_4)
		context.Dr7 |= (3 << (24 + dbgIndex * 2));
	else if (size == HWBP_SIZE_8)
		context.Dr7 |= (2 << (24 + dbgIndex * 2));
	else
		return false;

	// set hwbp address
	if (dbgIndex == 0)
		context.Dr0 = (ULONG_PTR)ptr;
	else if (dbgIndex == 1)
		context.Dr1 = (ULONG_PTR)ptr;
	else if (dbgIndex == 2)
		context.Dr2 = (ULONG_PTR)ptr;
	else if (dbgIndex == 3)
		context.Dr3 = (ULONG_PTR)ptr;

	// enable hwbp
	context.Dr7 |= 1 << (dbgIndex * 2);

	if (!optionalContext)
	{
		if (!SetThreadContext(hThread, &context))
			return false;
	}
	else
		*optionalContext = context;

	return true;
}

bool HardwareBP::RemoveHWBP(HANDLE hThread, void* ptr, PCONTEXT optionalContext)
{
	CONTEXT context;
	if (!optionalContext)
	{
		memset(&context, 0, sizeof(CONTEXT));
		context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		if (!GetThreadContext(hThread, &context))
			return false;
	}
	else
		context = *optionalContext;

	// find the hwbp of ptr and remove it
	if (context.Dr7 & (1 << 0))
		context.Dr7 &= ~(1 << 0);
	else if (context.Dr7 & (1 << 2))
		context.Dr7 &= ~(1 << 2);
	else if (context.Dr7 & (1 << 4))
		context.Dr7 &= ~(1 << 4);
	else if (context.Dr7 & (1 << 6))
		context.Dr7 &= ~(1 << 6);
	else
		return false;

	if (!optionalContext)
	{
		if (!SetThreadContext(hThread, &context))
			return false;
	}
	else
		*optionalContext = context;

	return true;
}

// ======== DETOUR ========

void CodeDetour::Detach()
{

}

// ======== VMT ========

void* VMTHook::Attach32(PULONG ppVTable, PBYTE pHook, unsigned index, bool bFlushCache)
{
	if (m_bHooked)
		return nullptr;

	m_iBitCount = 32;
	m_pOldVtable = ppVTable;
	m_uFuncIndex = index;

	DWORD oldProt, newProt;
	VirtualProtect((void*)(ppVTable + (index * 4)), 4, PAGE_EXECUTE_READWRITE, &oldProt);

	PBYTE pOrig = ((PBYTE)(ppVTable)[index]);
	m_pOriginalFunc = pOrig;
	((ULONG*)(ppVTable))[index] = (ULONG)pHook;

	VirtualProtect((void*)(ppVTable + (index * 4)), 4, oldProt, &newProt);

	if (bFlushCache)
		FlushInstructionCache(GetCurrentProcess(), (void*)(ppVTable + (index * 4)), 4);

	m_bHooked = true;

	return pOrig;
}

void* VMTHook::Attach64(PULONGLONG ppVTable, PBYTE pHook, unsigned index, bool bFlushCache)
{
	if (m_bHooked)
		return nullptr;

	m_iBitCount = 64;
	m_pOldVtable = ppVTable;
	m_uFuncIndex = index;

	DWORD oldProt, newProt;
	VirtualProtect((void*)(ppVTable + (index * 8)), 8, PAGE_EXECUTE_READWRITE, &oldProt);

	PBYTE pOrig = (PBYTE)(ppVTable[index]);
	m_pOriginalFunc = pOrig;
	((ULONGLONG*)(ppVTable))[index] = (ULONGLONG)pHook;

	VirtualProtect((void*)(ppVTable + (index * 8)), 8, oldProt, &newProt);

	if (bFlushCache)
		FlushInstructionCache(GetCurrentProcess(), (void*)(ppVTable + (index * 8)), 8);

	m_bHooked = true;

	return pOrig;
}

void VMTHook::Detach()
{
	DWORD oldProt, newProt;

	if (m_iBitCount == 32)
	{
		VirtualProtect((void*)((ULONG)m_pOldVtable + (m_uFuncIndex * 4)), 4, PAGE_EXECUTE_READWRITE, &oldProt);

		((ULONG*)(m_pOldVtable))[m_uFuncIndex] = (ULONG)m_pOriginalFunc;

		VirtualProtect((void*)((ULONG)m_pOldVtable + (m_uFuncIndex * 4)), 4, oldProt, &newProt);
	}
	else if (m_iBitCount == 64)
	{
		VirtualProtect((void*)((ULONGLONG)m_pOldVtable + (m_uFuncIndex * 8)), 8, PAGE_EXECUTE_READWRITE, &oldProt);

		((ULONGLONG*)(m_pOldVtable))[m_uFuncIndex] = (ULONGLONG)m_pOriginalFunc;

		VirtualProtect((void*)((ULONGLONG)m_pOldVtable + (m_uFuncIndex * 8)), 8, oldProt, &newProt);
	}

	m_bHooked = false;
}

// ======== IAT ========

void* IATHook::Attach(HMODULE hModule, char* szModule, char* szProc, void *pHook)
{
	if (m_bHooked)
		return nullptr;

	BYTE* ulBase = (BYTE*)hModule;

	m_pImage = (PIMAGE_DOS_HEADER)ulBase;
	m_pNtHeaders = (PIMAGE_NT_HEADERS)(ulBase + m_pImage->e_lfanew);

	if (m_pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	m_pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(ulBase + m_pNtHeaders->OptionalHeader.DataDirectory[1].VirtualAddress);

	while (m_pImportDesc->Name) 
	{
		if (!strcmp((char*)(ulBase + m_pImportDesc->Name), szModule))
		{
			m_pThunk = (PIMAGE_THUNK_DATA)(ulBase + m_pImportDesc->FirstThunk);
			m_pOrigThunk = (PIMAGE_THUNK_DATA)(ulBase + m_pImportDesc->OriginalFirstThunk);

			while (m_pThunk->u1.Function) 
			{
				m_pName = (PIMAGE_IMPORT_BY_NAME)(ulBase + m_pOrigThunk->u1.AddressOfData);
				
				if (!strcmp((char*)m_pName->Name, szProc))
				{
					DWORD oldProt;
					MEMORY_BASIC_INFORMATION mbi;

					if (!VirtualQuery(m_pThunk, &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
						return nullptr;

					m_pRegionBase = mbi.BaseAddress;
					m_uRegionSize = mbi.RegionSize;
					VirtualProtect(m_pRegionBase, m_uRegionSize, PAGE_EXECUTE_READWRITE, &mbi.Protect);

					void *oldPtr = (void*)m_pThunk->u1.Function;
					*(BYTE**)(&(m_pThunk->u1.Function)) = (BYTE*)pHook;

					VirtualProtect(m_pRegionBase, m_uRegionSize, mbi.Protect, &oldProt);

					m_pOldPtr = oldPtr;

					m_bHooked = true;
					return oldPtr;
				}

				m_pThunk++;
				m_pOrigThunk++;
			}
		}

		m_pImportDesc++;
	}

	return nullptr;
}

void IATHook::Detach()
{
	if (!m_bHooked)
		return;

	DWORD oldProt, newProt;
	VirtualProtect(m_pRegionBase, m_uRegionSize, PAGE_EXECUTE_READWRITE, &oldProt);
	*(BYTE**)(&(m_pThunk->u1.Function)) = (BYTE*)m_pOldPtr;

	VirtualProtect(m_pRegionBase, m_uRegionSize, oldProt, &newProt);

	m_bHooked = false;
}

// ======== YUNOHOOK ========

YUNOHook::YUNOHook()
{
}

YUNOHook::~YUNOHook()
{
}

char* YUNOHook::CreateName(char* szHookName)
{
	char* szHookNameCopy = 0;
	if (szHookName) // its a string
	{
		szHookNameCopy = new char[strlen(szHookName) + 1];
		memset(szHookNameCopy, 0, strlen(szHookName) + 1);
		memcpy(szHookNameCopy, szHookName, strlen(szHookName));
	}
	else
	{
		szHookNameCopy = new char[2];
		memset(szHookNameCopy, 0, 2);
	}

	return szHookNameCopy;
}

YUNOHook::EReturnStatus YUNOHook::AddHWBP(char* szHookName, DWORD dwThreadId, HardwareBP::EHWBP_TYPE type, HardwareBP::EHWBP_SIZE size, void* pAddress, PCONTEXT optionalContext, HardwareBP::HWBP_Callback pHook)
{
	HardwareBP* pHWBP = new HardwareBP;

	char* szAllocatedHookName = CreateName(szHookName);

	if (!pHWBP->IsHandlerAttached())
		pHWBP->AttachHandler();

	HardwareBPHooks.push_back(std::make_pair(pHWBP, szAllocatedHookName));

	if (!pHWBP->Attach(dwThreadId, type, size, pAddress, optionalContext, pHook))
		HOOK_FAILED;

	return HOOK_SUCCESS;
}

YUNOHook::EReturnStatus YUNOHook::AddHWBPAllThreads(char* szHookName, HardwareBP::EHWBP_TYPE type, HardwareBP::EHWBP_SIZE size, void* pAddress, HardwareBP::HWBP_Callback pHook)
{
	HardwareBP* pHWBP = new HardwareBP;

	char* szAllocatedHookName = CreateName(szHookName);

	if (!pHWBP->IsHandlerAttached())
		pHWBP->AttachHandler();

	HardwareBPHooks.push_back(std::make_pair(pHWBP, szAllocatedHookName));

	if (!pHWBP->AttachAllThreads(type, size, pAddress, pHook))
		return HOOK_FAILED;

	return HOOK_SUCCESS;
}

YUNOHook::EReturnStatus YUNOHook::AddPageBP(char* szHookName, BYTE* pAddress, PageBP::PageBP_Callback pHook)
{
	PageBP* pPageBP = new PageBP;

	char* szAllocatedHookName = CreateName(szHookName);

	if (!pPageBP->IsHandlerAttached())
		pPageBP->AttachHandler();

	PageBPHooks.push_back(std::make_pair(pPageBP, szAllocatedHookName));

	pPageBP->Attach(pAddress, pHook);

	return HOOK_SUCCESS;
}

YUNOHook::EReturnStatus YUNOHook::AddIATHook(char* szHookName, HMODULE hModule, char* szModule, char* szProc, void* pHook)
{
	IATHook* pIatHook = new IATHook;

	char* szAllocatedHookName = CreateName(szHookName);

	void* pReturn = pIatHook->Attach(hModule, szModule, szProc, pHook);

	if (pReturn == nullptr)
		return HOOK_FAILED;

	IATHooks.push_back(std::make_pair(pIatHook, szAllocatedHookName));

	return HOOK_SUCCESS;
}

YUNOHook::EReturnStatus YUNOHook::AddVtableHook32(char* szHookName, PULONG ppVTable, PBYTE pHook, unsigned index, bool bFlushCache, PULONG pOriginalFunc /*for calling original func*/)
{
	VMTHook* pVmtHook = new VMTHook;

	char* szAllocatedHookName = CreateName(szHookName);

	void* ret = 0;
	ret = pVmtHook->Attach32(ppVTable, pHook, index, bFlushCache);

	if (pOriginalFunc)
		*pOriginalFunc = (ULONG)ret;

	VMTHooks.push_back(std::make_pair(pVmtHook, szAllocatedHookName));

	return HOOK_SUCCESS;
}

YUNOHook::EReturnStatus YUNOHook::AddVtableHook64(char* szHookName, PULONGLONG ppVTable, PBYTE pHook, unsigned index, bool bFlushCache, PULONGLONG pOriginalFunc /*for calling original func*/)
{
	VMTHook* pVmtHook = new VMTHook;

	char* szAllocatedHookName = CreateName(szHookName);

	void* ret = 0;
	ret = pVmtHook->Attach64(ppVTable, pHook, index, bFlushCache);

	if (pOriginalFunc)
		*pOriginalFunc = (ULONGLONG)ret;

	VMTHooks.push_back(std::make_pair(pVmtHook, szAllocatedHookName));

	return HOOK_SUCCESS;
}

void YUNOHook::DetachAll()
{
	for (auto& i : CodeBPHooks)
	{
		i.first->Detach();
		delete[] i.second;
	}
	CodeBPHooks.clear();

	for (auto& i : PageBPHooks)
	{
		i.first->Detach();
		delete[] i.second;
	}
	PageBPHooks.clear();
	PageBP::DetachHandler();

	for (auto& i : HardwareBPHooks)
	{
		i.first->Detach();
		delete[] i.second;
	}
	HardwareBPHooks.clear();
	HardwareBP::DetachHandler();

	for (auto& i : CodeDetourHooks)
	{
		i.first->Detach();
		delete[] i.second;
	}
	CodeDetourHooks.clear();

	for (auto& i : VMTHooks) 
	{
		i.first->Detach();
		delete[] i.second;
	}
	VMTHooks.clear();
	
	for (auto& i : IATHooks) 
	{
		i.first->Detach();
		delete[] i.second;
	}
	IATHooks.clear();

}

bool YUNOHook::Detach(char* szName)
{
	// find from int3's
	for (size_t i = 0; i < CodeBPHooks.size(); i++)
	{
		if ((int)(CodeBPHooks[i].second) > 10000)
		{
			if (!strcmp(CodeBPHooks[i].second, szName))
			{
				CodeBPHooks[i].first->Detach();
				delete[] CodeBPHooks[i].second;
				CodeBPHooks.erase(CodeBPHooks.begin() + i);
				return true;
			}
		}
	}

	// find from pagehook's
	for (size_t i = 0; i < PageBPHooks.size(); i++)
	{
		if ((int)(PageBPHooks[i].second) > 10000)
		{
			if (!strcmp(PageBPHooks[i].second, szName))
			{
				PageBPHooks[i].first->Detach();
				delete[] PageBPHooks[i].second;
				PageBPHooks.erase(PageBPHooks.begin() + i);
				return true;
			}
		}
	}

	// find from hwbp's
	for (size_t i = 0; i < HardwareBPHooks.size(); i++)
	{
		if ((int)(HardwareBPHooks[i].second) > 10000)
		{
			if (!strcmp(HardwareBPHooks[i].second, szName))
			{
				HardwareBPHooks[i].first->Detach();
				delete[] HardwareBPHooks[i].second;
				HardwareBPHooks.erase(HardwareBPHooks.begin() + i);
				return true;
			}
		}
	}

	// find from codedetours's
	for (size_t i = 0; i < CodeDetourHooks.size(); i++)
	{
		if ((int)(CodeDetourHooks[i].second) > 10000)
		{
			if (!strcmp(CodeDetourHooks[i].second, szName))
			{
				CodeDetourHooks[i].first->Detach();
				delete[] CodeDetourHooks[i].second;
				CodeDetourHooks.erase(CodeDetourHooks.begin() + i);
				return true;
			}
		}
	}

	// find from vmt's
	for (size_t i = 0; i < VMTHooks.size(); i++)
	{
		if ((int)(VMTHooks[i].second) > 10000)
		{
			if (!strcmp(VMTHooks[i].second, szName))
			{
				VMTHooks[i].first->Detach();
				delete[] VMTHooks[i].second;
				VMTHooks.erase(VMTHooks.begin() + i);
				return true;
			}
		}
	}

	// find from iat's
	for (size_t i = 0; i < IATHooks.size(); i++)
	{
		if ((int)(IATHooks[i].second) > 10000)
		{
			if (!strcmp(IATHooks[i].second, szName))
			{
				IATHooks[i].first->Detach();
				delete[] IATHooks[i].second;
				IATHooks.erase(IATHooks.begin() + i);
				return true;
			}
		}
	}

	return false;
}
