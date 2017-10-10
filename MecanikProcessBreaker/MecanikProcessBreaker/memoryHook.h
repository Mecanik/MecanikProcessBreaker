#pragma once
#include <windows.h>
#include <list>

using namespace std;

typedef VOID(*HookCallback)(PCONTEXT);

struct HookStruct
{
	DWORD HookLocation;
	HookCallback Callback;
	DWORD originalProtection;
};

class memoryHook
{
public:
	static void add(DWORD address, HookCallback jump);
	static void remove(DWORD address);

	static DWORD* getArg(PCONTEXT ctx, int num);
	static void setArg(PCONTEXT ctx, int num, DWORD value);
	static DWORD* getReturnAddress(PCONTEXT ctx);
	static void setReturnAddress(PCONTEXT ctx, DWORD value);

private:
	static bool initialized;
	static list<HookStruct> hooks;
	static DWORD replaceHook;

	static DWORD* getValueFromStack(PCONTEXT ctx, DWORD offset);
	static void setValueToStack(PCONTEXT ctx, DWORD offset, DWORD value);

	static unsigned long hookHandler(PEXCEPTION_POINTERS exc);
};
