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

#pragma once

#include "CriticalSection.h"

typedef NTSTATUS(WINAPI*LDRLOADDLL)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);

struct PROCESS_CACHE_INFO
{
	DWORD ProcessId;
	DWORD TickCount;
};

class ProcessManager
{
public:
	ProcessManager();
	virtual ~ProcessManager();
	void ClearProcessCache();
	bool AddProcessCache(DWORD ProcessId);
	bool GetProcessCache(PROCESS_CACHE_INFO* lpProcessCacheInfo, DWORD ProcessId);
	void InsertProcessCacheInfo(PROCESS_CACHE_INFO ProcessCacheInfo);
	void RemoveProcessCacheInfo(PROCESS_CACHE_INFO ProcessCacheInfo);
	bool ListAllProcess(HWND hwndList);
	char SelectedPID[MAX_PATH];
private:
	CCriticalSection m_critical;
	std::map<DWORD, PROCESS_CACHE_INFO> m_ProcessCacheInfo;
};

extern ProcessManager T_ProcessManager;