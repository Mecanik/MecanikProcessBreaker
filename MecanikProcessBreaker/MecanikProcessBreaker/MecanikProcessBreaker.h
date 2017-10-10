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

#include "MNTDetours.h"
#include "Console.h"

namespace MecanikProcessBreaker
{


	class MecanikProcessBreaker
	{
	public:
		MecanikProcessBreaker();
		virtual ~MecanikProcessBreaker();
		static VOID WINAPI StartRippingFunctions();

		/** Define here each function you want to RIP! */
		static int __stdcall MyWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
		static int __stdcall MyWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED  lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

		static int __stdcall MySend(SOCKET s, const char *buf, int len, int flags);
		static int __stdcall MyRecv(SOCKET s, char *buf, int len, int flags);
		static int __stdcall MyConnect(SOCKET s, const struct sockaddr *name, int namelen);
		static int __stdcall MyClosesocket(SOCKET s);
		static int __stdcall MyWSAAsyncSelect(SOCKET s,HWND hWnd,unsigned int wMsg,long lEvent);

		static void __stdcall MyOutputDebugStringA(LPCSTR lpOutput);
		static void __stdcall MyOutputDebugStringW(LPCSTR lpOutput);
		static BOOL WINAPI MyQueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
		static BOOL WINAPI MyQueryPerformanceFrequency(LARGE_INTEGER *lpPerformanceCount );

		/** Define here each critical section, for each function you will add! */
		CRITICAL_SECTION MyWSASend_Critical,
			MyWSARecv_Critical,
			OutputDebugStringW_Critical,
			OutputDebugStringA_Critical,
			MySend_Critical,
			MyRecv_Critical,
			MyConnect_Critical,
			MyClosesocket_Critical,
			MyWSAAsyncSelect_Critical,
			MyQueryPerformanceCounter_Critical,
			MyQueryPerformanceFrequency_Critical;

		BYTE MyWSASendHook[6];
		BYTE MyWSARecvHook[6];
		BYTE MyOutputDebugStringWHook[6];
		BYTE MyOutputDebugStringAHook[6];
		BYTE MySendHook[6];
		BYTE MyRecvHook[6];
		BYTE MyConnectHook[6];
		BYTE MyClosesocketHook[6];
		BYTE MyWSAAsyncSelectHook[6];
		BYTE MyQueryPerformanceCounterHook[6];
		BYTE MyQueryPerformanceFrequencyHook[6];
	};
	extern MecanikProcessBreaker T_MecanikProcessBreaker;
}
