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
#include "ProcessManager.h"
#include "Utils.h"

ProcessManager T_ProcessManager;

ProcessManager::ProcessManager()
{
	memset(&this->SelectedPID, 0, sizeof(this->SelectedPID));
}


ProcessManager::~ProcessManager()
{
}

bool ProcessManager::ListAllProcess(HWND hwndList)
{
	DWORD ProcessIds[1024], BytesReturned = 0, ProcessCount = 0;

	if (EnumProcesses(ProcessIds, sizeof(ProcessIds), &BytesReturned) == 0)
	{
		return 0;
	}

	for (int n = 0, ProcessCount = (BytesReturned / sizeof(DWORD));n < ProcessCount;n++)
	{
		LVITEM lvi;
		memset(&lvi, 0, sizeof(LVITEM));

		lvi.pszText		= LPSTR_TEXTCALLBACK; // Sends an LVN_GETDISPINFO message.
		lvi.mask		= LVIF_TEXT | LVIF_STATE;
		lvi.state		= 0;
		lvi.stateMask	= 0;
		lvi.iItem		= n;
		lvi.iSubItem	= 0;
		lvi.lParam		= n; //LOL

		ListView_InsertItem(hwndList, &lvi);

		SendMessageA(hwndList, LVM_SETCOLUMNWIDTH, 0, 30);
		SendMessageA(hwndList, LVM_SETCOLUMNWIDTH, 1, 100);
		SendMessageA(hwndList, LVM_SETCOLUMNWIDTH, 2, 200);
		SendMessageA(hwndList, LVM_SETCOLUMNWIDTH, 3, 500);

		if (ProcessIds[n] != 0)
		{
			TCHAR buffer[50], buffer2[MAX_PATH];

			sprintf_s(buffer, TEXT("%d"), n);
			ListView_SetItemText(hwndList, n, 0, (LPTSTR)buffer);

			sprintf_s(buffer, TEXT("%u"), ProcessIds[n]);
			ListView_SetItemText(hwndList, n, 1, (LPTSTR)buffer);
			
			if (this->AddProcessCache(ProcessIds[n]) != 0)
			{
				TCHAR REALProcessName[MAX_PATH] = TEXT("<unknown>");
				char szProcessName[MAX_PATH], sTemp[MAX_PATH];

				HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessIds[n]);

				if (hProcess != NULL)
				{
					if (GetProcessImageFileNameA(hProcess, szProcessName, MAX_PATH) != 0)
					{
						if (ConvertProcessImageFileNameA(szProcessName, sTemp, MAX_PATH) != 0)
						{
							if (GetModuleBaseName(hProcess, 0, REALProcessName, MAX_PATH) != 0)
							{
								ListView_SetItemText(hwndList, n, 2, (LPTSTR)REALProcessName);
								ListView_SetItemText(hwndList, n, 3, (LPTSTR)sTemp);
								CloseHandle(hProcess);
							}
							else
							{
								ListView_SetItemText(hwndList, n, 2, (LPTSTR)TEXT("< unknown >"));
								ListView_SetItemText(hwndList, n, 3, (LPTSTR)sTemp);
								CloseHandle(hProcess);
							}
						}
						else
						{
							CloseHandle(hProcess);
						}
					}
					else
					{
						CloseHandle(hProcess);
					}
				} else if (hProcess == NULL) {

					LPVOID lpMsgBuf;
					LPVOID lpDisplayBuf;
					DWORD dw = GetLastError();

					FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);

					lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)"OpenProcess") + 100) * sizeof(TCHAR));
					StringCchPrintf((LPTSTR)lpDisplayBuf, LocalSize(lpDisplayBuf) / sizeof(TCHAR), TEXT("%s failed with error %d: %s ( try the x64 version? )"), "OpenProcess", dw, lpMsgBuf);

					ListView_SetItemText(hwndList, n, 2, (LPTSTR)TEXT("< unknown >"));
					ListView_SetItemText(hwndList, n, 3, (LPTSTR)TEXT(lpDisplayBuf));

					LocalFree(lpMsgBuf);
					LocalFree(lpDisplayBuf);

					SetFocus(hwndList);
				}
			}
		}
	}

	return 1;
}


void ProcessManager::ClearProcessCache() // OK
{
	this->m_critical.lock();

	for (std::map<DWORD, PROCESS_CACHE_INFO>::iterator it = this->m_ProcessCacheInfo.begin();it != this->m_ProcessCacheInfo.end();)
	{
		if ((GetTickCount() - it->second.TickCount) < 300000)
		{
			it++;
		}
		else
		{
			it = this->m_ProcessCacheInfo.erase(it);
		}
	}

	this->m_critical.unlock();
}

bool ProcessManager::GetProcessCache(PROCESS_CACHE_INFO* lpProcessCacheInfo, DWORD ProcessId)
{
	this->m_critical.lock();

	std::map<DWORD, PROCESS_CACHE_INFO>::iterator it = this->m_ProcessCacheInfo.find(ProcessId);

	if (it != this->m_ProcessCacheInfo.end())
	{
		(*lpProcessCacheInfo) = it->second;
		this->m_critical.unlock();
		return 1;
	}

	this->m_critical.unlock();
	return 0;
}

void ProcessManager::InsertProcessCacheInfo(PROCESS_CACHE_INFO ProcessCacheInfo)
{
	this->m_critical.lock();

	std::map<DWORD, PROCESS_CACHE_INFO>::iterator it = this->m_ProcessCacheInfo.find(ProcessCacheInfo.ProcessId);

	if (it == this->m_ProcessCacheInfo.end())
	{
		this->m_ProcessCacheInfo.insert(std::pair<DWORD, PROCESS_CACHE_INFO>(ProcessCacheInfo.ProcessId, ProcessCacheInfo));
	}
	else
	{
		it->second = ProcessCacheInfo;
	}

	this->m_critical.unlock();
}

void ProcessManager::RemoveProcessCacheInfo(PROCESS_CACHE_INFO ProcessCacheInfo)
{
	this->m_critical.lock();

	std::map<DWORD, PROCESS_CACHE_INFO>::iterator it = this->m_ProcessCacheInfo.find(ProcessCacheInfo.ProcessId);

	if (it != this->m_ProcessCacheInfo.end())
	{
		this->m_ProcessCacheInfo.erase(it);
		this->m_critical.unlock();
		return;
	}

	this->m_critical.unlock();
}

bool ProcessManager::AddProcessCache(DWORD ProcessId)
{
	PROCESS_CACHE_INFO ProcessCacheInfo;

	if (this->GetProcessCache(&ProcessCacheInfo, ProcessId) != 0)
	{
		return 0;
	}

	ProcessCacheInfo.ProcessId = ProcessId;

	ProcessCacheInfo.TickCount = GetTickCount();

	this->InsertProcessCacheInfo(ProcessCacheInfo);

	return 1;
}