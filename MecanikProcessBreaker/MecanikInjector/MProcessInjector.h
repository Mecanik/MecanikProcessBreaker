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

#include "stdafx.h"
#include "CMap.hpp"

#define THREAD_ALL_ACCESS_VISTA (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)


//SOURCE: http://processhacker.sourceforge.net/doc/ntpsapi_8h_source.html
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // ?
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR 0x00000010 // ?
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET 0x00000020 // ?
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080

namespace MecanikInjector
{
	typedef struct _CLIENT_ID
	{
		PVOID UniqueProcess;
		PVOID UniqueThread;
	} CLIENT_ID, *PCLIENT_ID;


	class MProcessInjector
	{
	public:
		MProcessInjector();
		virtual ~MProcessInjector();

		bool CheckProcessModule(HANDLE ProcessHandle, char* ModulePath);
		bool StartProcessModule(HANDLE ProcessHandle, char* ModulePath, int ModulePathSize);
		bool StartProcessNTModule(char* ModulePath, DWORD dwProcessId);
		std::string GetProcessName(DWORD aPid);

	private:
		void GetSystemMessage(char* Function);
		static inline void InternalInit();
	};

	extern MProcessInjector T_MProcessInjector;
}