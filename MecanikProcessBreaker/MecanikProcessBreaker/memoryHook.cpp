#include "stdafx.h"
#include "memoryHook.h"
bool memoryHook::initialized;
list<HookStruct> memoryHook::hooks;
DWORD memoryHook::replaceHook = 0;


void memoryHook::add(DWORD address, HookCallback callback)
{
	if (!initialized)
	{
		initialized = true;
		AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)hookHandler);
	}

	HookStruct newHook;
	newHook.HookLocation = address;
	newHook.Callback = callback;

	DWORD oldAccess;
	VirtualProtect((LPVOID)address, 1, PAGE_NOACCESS, &oldAccess);

	newHook.originalProtection = oldAccess;

	hooks.push_back(newHook);
}

void memoryHook::remove(DWORD address)
{
	list<HookStruct>::iterator hook;
	for (hook = hooks.begin(); hook != hooks.end(); hook++)
	{
		if (hook->HookLocation == address)
		{
			hooks.erase(hook);
			break;
		}
	}
}

DWORD* memoryHook::getArg(PCONTEXT ctx, int num)
{
	return getValueFromStack(ctx, sizeof(PVOID) * (num + 1));
}
void memoryHook::setArg(PCONTEXT ctx, int num, DWORD value)
{
	*getArg(ctx, num) = value;
}

DWORD* memoryHook::getReturnAddress(PCONTEXT ctx)
{
	return getValueFromStack(ctx, 0);
}
void memoryHook::setReturnAddress(PCONTEXT ctx, DWORD value)
{
	*getReturnAddress(ctx) = value;
}

DWORD* memoryHook::getValueFromStack(PCONTEXT ctx, DWORD offset)
{
#ifdef _WIN64 || __amd64__
	return (DWORD*)(ctx->Rsp + offset);
#else
	return (DWORD*)(ctx->Esp + offset);
#endif
}
void memoryHook::setValueToStack(PCONTEXT ctx, DWORD offset, DWORD value)
{
	*getValueFromStack(ctx, offset) = value;
}

unsigned long memoryHook::hookHandler(PEXCEPTION_POINTERS exc)
{
#ifdef _WIN64 || __amd64__
	DWORD instructionPtr = exc->ContextRecord->Rip;
#else
	DWORD instructionPtr = exc->ContextRecord->Eip;
#endif

	if (exc->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		if (replaceHook)
		{
			DWORD oldAccess;
			VirtualProtect((LPVOID)replaceHook, 1, PAGE_NOACCESS, &oldAccess);

			replaceHook = 0;
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	else if (exc->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
	{
		HookStruct activeHook = { 0 };
		list<HookStruct>::iterator hook;
		for (hook = hooks.begin(); hook != hooks.end(); hook++)
		{
			if (hook->HookLocation == instructionPtr)
			{
				activeHook = *hook;
				break;
			}
		}

		if (activeHook.HookLocation)
		{
			replaceHook = activeHook.HookLocation;
			activeHook.Callback(exc->ContextRecord);
			DWORD oldAccess;
			VirtualProtect((LPVOID)replaceHook, 1, activeHook.originalProtection, &oldAccess);
		}

		exc->ContextRecord->EFlags |= 0x100;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}