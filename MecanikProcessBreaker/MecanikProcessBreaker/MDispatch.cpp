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
#include "MDispatch.h"
#include "MNTDetours.h"
#include "MecanikProcessBreaker.h"
#include "HideModule.h"

namespace MecanikDispatcher
{
	MDispatch _MecanikModule;

	MDispatch::MDispatch()
	{
		M_Console.InitCore();

		this->m_hRunMonitor = CreateEvent(0, 1, 0, _T("MECANIK_PROCESS_BREAKER_EVENT"));
		this->m_hDisPatchMonitor = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)DispatchMonitor, this, 0, 0);
	}

	MDispatch::~MDispatch()
	{
		this->InternalExit();
	}

	void MDispatch::OnAttach(HMODULE hModule)
	{
		this->m_Instance = hModule;
		this->InternalInit();
	}

	void MDispatch::OnDetach(HMODULE hModule)
	{
		this->m_Instance = hModule;
		this->InternalExit();
	}

	bool MDispatch::InternalInit()
	{
		MecanikDetours::MNTDetours::NTHook();
		MecanikProcessBreaker::MecanikProcessBreaker::StartRippingFunctions();
		SetEvent(m_hRunMonitor);
		return true;
	}

	int MDispatch::InternalExit(void)
	{
		M_Console.Terminate();
		if (_MecanikModule.m_hDisPatchMonitor != 0 && _MecanikModule.m_hDisPatchMonitor != INVALID_HANDLE_VALUE)
		{
			TerminateThread(_MecanikModule.m_hDisPatchMonitor, 0);
			CloseHandle(_MecanikModule.m_hDisPatchMonitor);
		}

		if (_MecanikModule.m_hRunMonitor)
		{
			CloseHandle(_MecanikModule.m_hRunMonitor);
		}
	
		return 0;
	}

	DWORD WINAPI MDispatch::DispatchMonitor(MDispatch* pThis)
	{
		if (!pThis) {
			return 0;
		}

		while (1)
		{
			if (WAIT_TIMEOUT != WaitForSingleObject(pThis->m_hRunMonitor, 0))
			{
				M_Console.ConsoleOutput(5, "[DispatchMonitor] :: Running fine :)");

				HideModule(_MecanikModule.m_Instance);
			}

			Sleep(60000);
		}

		return 0;
	}
}
