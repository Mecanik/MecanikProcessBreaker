#pragma once

#include <Windows.h>
#include <iostream>
#include <vector>
#include <TlHelp32.h>
#include <Wtsapi32.h>
#include <Userenv.h>
#include <Aclapi.h>
#include <string>
#include <Sddl.h>
#include <psapi.h>
#include <Shlwapi.h>

#pragma comment(lib,"Wtsapi32.lib")
#pragma comment(lib,"Userenv.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "psapi.lib")

#pragma comment(lib,"ws2_32.lib")

#pragma warning( disable : 4067 4018 4838 4309 4996 4996 4996 4996)

#if(USE_VMPROTECT == 1)
#include <VirtualizerSDK.h>
#ifdef _WIN64 
#pragma comment(lib,"VirtualizerSDK64")
#elif _WIN32
#pragma comment(lib,"VirtualizerSDK32")
#endif
#else
#define VIRTUALIZER_TIGER_BLACK_START
#define VIRTUALIZER_TIGER_BLACK_END
#define VIRTUALIZER_TIGER_WHITE_START
#define VIRTUALIZER_TIGER_WHITE_END
static void VirtualizerStart() {}
static void VirtualizerEnd() {}
#endif



