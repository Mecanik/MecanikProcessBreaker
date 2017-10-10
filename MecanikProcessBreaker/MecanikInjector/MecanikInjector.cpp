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

// MecanikInjector.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "MecanikInjector.h"
#include "Utils.h"
#include "Process.h"


#define MAX_LOADSTRING 100

HWND hWnd;
HWND hwndList;
HWND hwndListLog;

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    SimpleProcessList(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance,  _In_ LPWSTR    lpCmdLine, _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_MECANIKINJECTOR, szWindowClass, MAX_LOADSTRING);

    MyRegisterClass(hInstance);

    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

	if (SetAdminPrivilege(SE_DEBUG_NAME) == 0)
	{
		MessageBoxA(GetActiveWindow(), "You need to run this application as an Administrator.", "Error", MB_OK | MB_ICONEXCLAMATION);
		ExitProcess(0);
		return FALSE;
	}

	if (IsElevated() == 0)
	{
		MessageBoxA(GetActiveWindow(), "The current user you are logged not is not Elevated.", "Error", MB_OK | MB_ICONEXCLAMATION);
		ExitProcess(0);
		return FALSE;
	}

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_MECANIKINJECTOR));

    MSG msg;

	DialogBox(hInst, MAKEINTRESOURCE(IDD_DIALOG_SIMPLEPROCESSLIST), hWnd, SimpleProcessList);

    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}

ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_MECANIKINJECTOR));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_MECANIKINJECTOR);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance;

   hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd) {
      return FALSE;
   }

   ShowWindow(hWnd, SW_HIDE);
   UpdateWindow(hWnd);

   return TRUE;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
               DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);	
            break;

            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            // TODO: Add any drawing code that uses hdc here...
			SetBkMode(hdc, TRANSPARENT);
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

INT_PTR CALLBACK SimpleProcessList(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);

	hwndList = GetDlgItem(hDlg, IDC_LIST1);
	hwndListLog = GetDlgItem(hDlg, IDC_LIST_LOG);

	switch (message)
	{

	case WM_NOTIFY:
	{
		switch (LOWORD(wParam))
		{
			case IDC_LIST1:
			{
				NMLVDISPINFO* plvdi = (NMLVDISPINFO*)lParam;

				if (plvdi->hdr.hwndFrom == hwndList &&plvdi->hdr.code == NM_CUSTOMDRAW)
				{
					SetWindowLong(hDlg, 0, (LONG)ProcessCustomDraw(lParam));
					return TRUE;
				}

				if (plvdi->hdr.hwndFrom == hwndList && ((LPNMHDR)lParam)->code == NM_CLICK) // NM_CLICK
				{
					char Text1[255],Text2[255],Text3[255],Text4[255],Text5[255] = { 0 };
					char Temp1[255],Temp2[255],Temp3[255],Temp4[255],Temp5[255] = { 0 };

					int iSlected = 0;
					int j = 0;

					iSlected = SendMessage(hwndList, LVM_GETNEXTITEM, -1, LVNI_FOCUSED);

					if (iSlected == -1)
					{
						break;
					}

					LVITEM LvItem;
					memset(&LvItem, 0, sizeof(LvItem));
					LvItem.mask			= LVIF_TEXT;
					LvItem.iSubItem		= 1;
					LvItem.pszText		= Text1;
					LvItem.cchTextMax	= 256;
					LvItem.iItem		= iSlected;

					SendMessage(hwndList, LVM_GETITEMTEXT, iSlected, (LPARAM)&LvItem);

					memset(&T_ProcessManager.SelectedPID, 0, sizeof(T_ProcessManager.SelectedPID));
					sprintf_s(T_ProcessManager.SelectedPID, Text1);

					StringCbPrintf(Temp1, ARRAYSIZE(Temp1), TEXT("Inject process with PID: [%s]"), Text1);

					SetDlgItemText(hDlg, IDOK, Temp1);

					LVITEM LvItem2;
					memset(&LvItem2, 0, sizeof(LvItem2));
					LvItem2.mask		= LVIF_TEXT;
					LvItem2.iSubItem	= 2;
					LvItem2.pszText		= Text2;
					LvItem2.cchTextMax	= 256;
					LvItem2.iItem		= iSlected;
					
					SendMessage(hwndList, LVM_GETITEMTEXT, iSlected, (LPARAM)&LvItem2);

					StringCbPrintf(Temp2, ARRAYSIZE(Temp2), TEXT("Process Name: [%s]"), Text2);

					SetDlgItemText(hDlg, IDC_PROCESS_NAME, Temp2);

					LVITEM LvItem3;
					memset(&LvItem3, 0, sizeof(LvItem3));
					LvItem3.mask		= LVIF_TEXT;
					LvItem3.iSubItem	= 3;
					LvItem3.pszText		= Text3;
					LvItem3.cchTextMax	= 256;
					LvItem3.iItem		= iSlected;

					SendMessage(hwndList, LVM_GETITEMTEXT, iSlected, (LPARAM)&LvItem3);

					StringCbPrintf(Temp3, ARRAYSIZE(Temp3), TEXT("Process Path: [%s]"), Text3);

					SetDlgItemText(hDlg, IDC_PROCESS_PATH, Temp3);

				}
			}
			break;
		}
	}

	case WM_CREATE:
	{
		return (INT_PTR)TRUE;
	}

	case WM_INITDIALOG:
	{
		SendMessage(GetDlgItem(hDlg, IDC_RADIO_ADVANCED), BM_SETCHECK, BST_CHECKED, 0);

		char buff[MAX_PATH];
		TCHAR szString[4][MAX_PATH] = { TEXT("#"), TEXT("PID"), TEXT("NAME"), TEXT("PATH") };

		ListView_SetExtendedListViewStyle(hwndList, LVS_EX_FULLROWSELECT);

		LVCOLUMN lvc;
		ListView_DeleteAllItems(hwndList);

		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;

		for (int k = 0; k < 4; k++)
		{
			lvc.iSubItem	= k;
			lvc.cx			= 100;
			lvc.pszText		= szString[k];
			lvc.fmt			= LVCFMT_LEFT;

			ListView_InsertColumn(hwndList, k, &lvc);
		}

		T_ProcessManager.ListAllProcess(hwndList);

		int pos = (int) SendMessage(hwndListLog, LB_ADDSTRING, 0, (LPARAM)"[LOG] :: Ready!");
		SendMessage(hwndListLog, LB_SETITEMDATA, pos, (LPARAM)0);

		return TRUE;
	}

	case WM_COMMAND:

		switch (LOWORD(wParam))
		{
			case IDC_BUTTON_REFRESH:
			{
				T_ProcessManager.ClearProcessCache();
				T_ProcessManager.ListAllProcess(hwndList);
				return (INT_PTR)TRUE;
			}

			case IDOK:
			{
				int iPosition = ListView_GetNextItem(hwndListLog, 0, LVNI_SELECTED);

				if (atoi(T_ProcessManager.SelectedPID) != 0 || atoi(T_ProcessManager.SelectedPID) != NULL | atoi(T_ProcessManager.SelectedPID) > 0)
				{
					char ModulePath[MAX_PATH];

					if (GetFullPathName(MECANIK_DLL, sizeof(ModulePath), ModulePath, 0) == 0)
					{
						MessageBoxA(hDlg, "You either deleted my .DLL or you are just dumb...\nMake sure that MecanikProcessBreaker.dll is present.", "ERROR", MB_OK | MB_ICONERROR);
						return 0;
					}

					if (IsDlgButtonChecked(hDlg, IDC_RADIO_simple))
					{
						SendMessage(hwndListLog, LB_ADDSTRING, iPosition, (LPARAM)"[LOG] :: Using SIMPLE method to break this process...");

						HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, atoi(T_ProcessManager.SelectedPID));

						if (ProcessHandle != 0)
						{
							if (MecanikInjector::T_MProcessInjector.CheckProcessModule(ProcessHandle, ModulePath) == 0)
							{
								if (MecanikInjector::T_MProcessInjector.StartProcessModule(ProcessHandle, ModulePath, strlen(ModulePath)) == 0)
								{
									char TMP[MAX_PATH] = { 0 };
									sprintf_s(TMP, "[LOG] :: PID [%d] Could not be injected....", atoi(T_ProcessManager.SelectedPID));
									int pos = (int)SendMessage(hwndListLog, LB_ADDSTRING, 0, (LPARAM)TMP);
									SendMessage(hwndListLog, LB_SETITEMDATA, pos, (LPARAM)0);
									MessageBoxA(hDlg, "This process could be injected!", "Error!", MB_OK | MB_ICONEXCLAMATION);
									CloseHandle(ProcessHandle);
								}
								else {
									char TMP[MAX_PATH] = { 0 };
									sprintf_s(TMP, "[LOG] :: PID [%d] Injection successful!", atoi(T_ProcessManager.SelectedPID));
									int pos = (int)SendMessage(hwndListLog, LB_ADDSTRING, 0, (LPARAM)TMP);
									SendMessage(hwndListLog, LB_SETITEMDATA, pos, (LPARAM)0);
									MessageBoxA(hDlg, "You have injected this process like a PRO!", "Congratulations!", MB_OK | MB_ICONINFORMATION);
									CloseHandle(ProcessHandle);
								}
							}
							else {
								CloseHandle(ProcessHandle);
							}
						}
					} else if (IsDlgButtonChecked(hDlg, IDC_RADIO_ADVANCED)) {

							SendMessage(hwndListLog, LB_ADDSTRING, iPosition, (LPARAM)"[LOG] :: Using ADVANCED method to break this process...  NICE ONE!");

							if (MecanikInjector::T_MProcessInjector.StartProcessNTModule(ModulePath, atoi(T_ProcessManager.SelectedPID)) == 0) {
									char TMP[MAX_PATH] = { 0 };
									sprintf_s(TMP, "[LOG] :: PID [%d] Could not be injected....", atoi(T_ProcessManager.SelectedPID));
									int pos = (int)SendMessage(hwndListLog, LB_ADDSTRING, 0, (LPARAM)TMP);
									SendMessage(hwndListLog, LB_SETITEMDATA, pos, (LPARAM)0);
									MessageBoxA(hDlg, "This process could be injected!", "Error!", MB_OK | MB_ICONEXCLAMATION);
								} else {

									std::string strNameProcess = MecanikInjector::T_MProcessInjector.GetProcessName(atoi(T_ProcessManager.SelectedPID)).c_str();
									std::wstring wstrDLLName = s2ws(MECANIK_DLL);

									Process * A = new Process(strNameProcess, wstrDLLName);

									char TMP[MAX_PATH] = { 0 };
									sprintf_s(TMP, "[LOG] :: PID [%d] Injection successful!", atoi(T_ProcessManager.SelectedPID));
									int pos = (int)SendMessage(hwndListLog, LB_ADDSTRING, 0, (LPARAM)TMP);
									SendMessage(hwndListLog, LB_SETITEMDATA, pos, (LPARAM)0);
									MessageBoxA(hDlg, "You have injected this process like a PRO!", "Congratulations!", MB_OK | MB_ICONINFORMATION);
								}
						}

					} else {
						MessageBoxA(hDlg, "You need to select a process to inject it... duh!", "ERROR", MB_OK | MB_ICONERROR);
					}
				return (INT_PTR)TRUE;
			}

			case IDCANCEL:
			{
				PostQuitMessage(0);
				EndDialog(hDlg, LOWORD(wParam));
			}

			return TRUE;
		}
	}

	return FALSE;
}