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

bool ConvertProcessImageFileNameA(char* path, char* out_path, DWORD out_path_size) // OK
{
	char driver[512];
	char device[MAX_PATH];
	char search[3] = " :";

	if (GetLogicalDriveStrings((sizeof(driver) - 1), driver) != 0)
	{
		char* fetch = driver;

		do
		{
			(*search) = (*fetch);

			if (QueryDosDevice(search, device, MAX_PATH) != 0)
			{
				std::string str = path;

				size_t index = str.find(device, 0);

				if (index != std::string::npos)
				{
					str.replace(index, (std::string(device).length() + 1), fetch);

					strcpy_s(out_path, out_path_size, str.data());

					return 1;
				}
			}

			while ((*fetch++) != 0);
		} while ((*fetch) != 0);
	}

	return 0;
}

bool ConvertProcessImageFileNameW(wchar_t* path, wchar_t* out_path, DWORD out_path_size)
{
	wchar_t driver[512];
	wchar_t device[MAX_PATH];
	wchar_t search[3] = L" :";

	if (GetLogicalDriveStringsW((sizeof(driver) - 1), driver) != 0)
	{
		wchar_t* fetch = driver;

		do
		{
			(*search) = (*fetch);

			if (QueryDosDeviceW(search, device, MAX_PATH) != 0)
			{
				std::wstring str = path;

				size_t index = str.find(device, 0);

				if (index != std::wstring::npos)
				{
					str.replace(index, (std::wstring(device).length() + 1), fetch);

					wcscpy_s(out_path, out_path_size, str.data());

					return 1;
				}
			}

			while ((*fetch++) != 0);
		} while ((*fetch) != 0);
	}

	return 0;
}

char* ConvertModuleFileName(char* name)
{
	static char buff[MAX_PATH] = { 0 };

	for (int n = strlen(name); n > 0; n--)
	{
		if (name[n] == '\\')
		{
			strcpy_s(buff, sizeof(buff), &name[(n + 1)]);
			break;
		}
	}

	return buff;
}

wchar_t* ConvertModuleFileName(wchar_t* name) // OK
{
	static wchar_t buff[MAX_PATH] = { 0 };

	for (int n = wcslen(name); n > 0; n--)
	{
		if (name[n] == '\\')
		{
			wcscpy_s(buff, sizeof(buff), &name[(n + 1)]);
			break;
		}
	}

	return buff;
}

inline const char * const BoolToString(const bool b)
{
	return b ? "TRUE" : "FALSE";
}

//convert string to wstring
std::wstring s2ws(const std::string & s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	std::wstring r(len, L'\0');
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, &r[0], len);
	return r;
}

bool SetAdminPrivilege(char* PrivilegeName)
{
	HANDLE TokenHandle;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &TokenHandle) == 0)
	{
		return 0;
	}

	LUID luid;

	if (LookupPrivilegeValue(0, PrivilegeName, &luid) == 0)
	{
		return 0;
	}

	TOKEN_PRIVILEGES tp;

	memset(&tp, 0, sizeof(tp));

	tp.PrivilegeCount = 1;

	tp.Privileges[0].Luid = luid;

	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (AdjustTokenPrivileges(TokenHandle, 0, &tp, sizeof(tp), 0, 0) == 0)
	{
		return 0;
	}

	return 1;
}
LRESULT ProcessCustomDraw(LPARAM lParam)
{
	LPNMLVCUSTOMDRAW lplvcd = (LPNMLVCUSTOMDRAW)lParam;

	switch (lplvcd->nmcd.dwDrawStage)
	{
	case CDDS_PREPAINT: //Before the paint cycle begins
						//request notifications for individual listview items
		return CDRF_NOTIFYITEMDRAW;

	case CDDS_ITEMPREPAINT: //Before an item is drawn
	{
		return CDRF_NOTIFYSUBITEMDRAW;
	}
	break;


	case CDDS_SUBITEM | CDDS_ITEMPREPAINT: //Before a subitem is drawn
	{
		switch (lplvcd->iSubItem)
		{
		case 0:
		{
			lplvcd->clrText = RGB(255, 255, 255);
			lplvcd->clrTextBk = RGB(0, 0, 0);
			return CDRF_NEWFONT;
		}
		break;

		case 1:
		{
			lplvcd->clrText = RGB(255, 255, 0);
			lplvcd->clrTextBk = RGB(0, 0, 0);
			return CDRF_NEWFONT;
		}
		break;

		case 2:
		{
			lplvcd->clrText = RGB(255, 0, 0);
			lplvcd->clrTextBk = RGB(0, 0, 0);
			return CDRF_NEWFONT;
		}
		break;

		case 3:
		{
			lplvcd->clrText = RGB(0, 255, 0);
			lplvcd->clrTextBk = RGB(0, 0, 0);
			return CDRF_NEWFONT;
		}
		break;

		case 4:
		{
			lplvcd->clrText = RGB(120, 0, 128);
			lplvcd->clrTextBk = RGB(20, 200, 200);
			return CDRF_NEWFONT;
		}
		break;

		case 5:
		{
			lplvcd->clrText = RGB(255, 255, 255);
			lplvcd->clrTextBk = RGB(0, 0, 150);
			return CDRF_NEWFONT;
		}
		break;

		}

	}
	}
	return CDRF_DODEFAULT;
}

BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}