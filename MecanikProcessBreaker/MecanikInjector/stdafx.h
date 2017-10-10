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

// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

#define PSAPI_VERSION 1

#define MECANIK_DLL "MecanikProcessBreaker.dll"

// Windows Header Files:
#include <windows.h>

// TODO: reference additional headers your program requires here
#include <Strsafe.h>
#include <commctrl.h>

#include <iostream>
#include <map>
#include <math.h>
#include <stdlib.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <Dbghelp.h>
#include <wchar.h>
#include <Rpc.h>
#include <winioctl.h>
#include <conio.h>
#include <dos.h>
#include <ShellAPI.h>
#include <tchar.h>
#include <iphlpapi.h>
#include <rpcdce.h>
#include <Winbase.h>
#include <tlhelp32.h>
#include <time.h>
#include <Csignal>
#include <Sys/types.h>
#include <Sys/stat.h>
#include <commctrl.h>
#include <process.h>
#include <Aclapi.h>
#include <Sddl.h>
#include <fstream>
#include <stdio.h>
#include <winternl.h>
#include <assert.h>
#include <exception>
#include <vector>
#include <algorithm>
#include <string>
#include <sstream>
#include <utility>
#include <io.h>
#include <iterator>
#include <lm.h>
#include <commctrl.h>

#pragma warning( disable : 4067 4018 4838 4309 4996 4996 4996 4996 4091 4101 4554)

#pragma comment(lib,"Psapi.lib")
#pragma comment(lib,"Shlwapi.lib")
#pragma comment(lib,"Dbghelp.lib")
#pragma comment(lib,"Rpcrt4.lib")
#pragma comment(lib,"Comctl32.lib")

#include "ProcessManager.h"
#include "MProcessInjector.h"

extern HWND hWnd;
extern HWND hwndList;
extern HWND hwndListLog;