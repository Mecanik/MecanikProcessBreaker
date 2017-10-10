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

// MecanikProcessBreaker.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "MecanikProcessBreaker.h"


namespace MecanikProcessBreaker
{
	MecanikProcessBreaker T_MecanikProcessBreaker;

	MecanikProcessBreaker::MecanikProcessBreaker()
	{
		/** Define here each critical section, for each function you will add! */
		InitializeCriticalSection(&MyWSASend_Critical);
		InitializeCriticalSection(&MyWSARecv_Critical);
		InitializeCriticalSection(&OutputDebugStringW_Critical);
		InitializeCriticalSection(&OutputDebugStringA_Critical);
		InitializeCriticalSection(&MySend_Critical);
		InitializeCriticalSection(&MyRecv_Critical);
		InitializeCriticalSection(&MyConnect_Critical);
		InitializeCriticalSection(&MyClosesocket_Critical);
		InitializeCriticalSection(&MyWSAAsyncSelect_Critical);
		InitializeCriticalSection(&MyQueryPerformanceCounter_Critical);
		InitializeCriticalSection(&MyQueryPerformanceFrequency_Critical);
	}


	MecanikProcessBreaker::~MecanikProcessBreaker()
	{
		/** Define here each critical section, for each function you will add! */
		/** We must work as clean as possible, because we are professionals! o.O */

		DeleteCriticalSection(&MyWSASend_Critical);
		DeleteCriticalSection(&MyWSARecv_Critical);
		DeleteCriticalSection(&OutputDebugStringW_Critical);
		DeleteCriticalSection(&OutputDebugStringA_Critical);
		DeleteCriticalSection(&MySend_Critical);
		DeleteCriticalSection(&MyRecv_Critical);
		DeleteCriticalSection(&MyConnect_Critical);
		DeleteCriticalSection(&MyClosesocket_Critical);
		DeleteCriticalSection(&MyWSAAsyncSelect_Critical);
		DeleteCriticalSection(&MyQueryPerformanceCounter_Critical);
		DeleteCriticalSection(&MyQueryPerformanceFrequency_Critical);
	}


	VOID WINAPI MecanikProcessBreaker::StartRippingFunctions()
	{
		// We can check if there is any IAT hooks on the functions we want to import!
		MecanikDetours::T_MNTDetours.CheckForIATHook("ws2_32.dll", "WSASend");
		MecanikDetours::T_MNTDetours.CheckForIATHook("ws2_32.dll", "WSASend");
		MecanikDetours::T_MNTDetours.CheckForIATHook("ws2_32.dll", "send");
		MecanikDetours::T_MNTDetours.CheckForIATHook("ws2_32.dll", "recv");
		MecanikDetours::T_MNTDetours.CheckForIATHook("ws2_32.dll", "connect");
		MecanikDetours::T_MNTDetours.CheckForIATHook("ws2_32.dll", "closesocket");
		MecanikDetours::T_MNTDetours.CheckForIATHook("ws2_32.dll", "WSAAsyncSelect");

		MecanikDetours::T_MNTDetours.CheckForIATHook("kernel32.dll", "OutputDebugStringW");
		MecanikDetours::T_MNTDetours.CheckForIATHook("kernel32.dll", "OutputDebugStringA");
		MecanikDetours::T_MNTDetours.CheckForIATHook("kernel32.dll", "GetTickCount");
		MecanikDetours::T_MNTDetours.CheckForIATHook("kernel32.dll", "QueryPerformanceCounter");
		MecanikDetours::T_MNTDetours.CheckForIATHook("kernel32.dll", "QueryPerformanceFrequency");

		// We can also check if the functions we want to import are already detoured/hooked!
		MecanikDetours::T_MNTDetours.CheckIfPatched("ws2_32.dll", "WSASend");
		MecanikDetours::T_MNTDetours.CheckIfPatched("ws2_32.dll", "WSASend");
		MecanikDetours::T_MNTDetours.CheckIfPatched("ws2_32.dll", "send");
		MecanikDetours::T_MNTDetours.CheckIfPatched("ws2_32.dll", "recv");
		MecanikDetours::T_MNTDetours.CheckIfPatched("ws2_32.dll", "connect");
		MecanikDetours::T_MNTDetours.CheckIfPatched("ws2_32.dll", "closesocket");
		MecanikDetours::T_MNTDetours.CheckIfPatched("ws2_32.dll", "WSAAsyncSelect");

		MecanikDetours::T_MNTDetours.CheckIfPatched("kernel32.dll", "OutputDebugStringW");
		MecanikDetours::T_MNTDetours.CheckIfPatched("kernel32.dll", "OutputDebugStringA");
		MecanikDetours::T_MNTDetours.CheckIfPatched("kernel32.dll", "GetTickCount");
		MecanikDetours::T_MNTDetours.CheckIfPatched("kernel32.dll", "QueryPerformanceCounter");
		MecanikDetours::T_MNTDetours.CheckIfPatched("kernel32.dll", "QueryPerformanceFrequency");

		// Here we do our "ripping"
		MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "WSASend", (LPVOID)T_MecanikProcessBreaker.MyWSASend, T_MecanikProcessBreaker.MyWSASendHook);
		MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "WSARecv", (LPVOID)T_MecanikProcessBreaker.MyWSARecv, T_MecanikProcessBreaker.MyWSARecvHook);
		MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "send", (LPVOID)T_MecanikProcessBreaker.MySend, T_MecanikProcessBreaker.MySendHook);
		MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "recv", (LPVOID)T_MecanikProcessBreaker.MyRecv, T_MecanikProcessBreaker.MyRecvHook);
		MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "connect", (LPVOID)T_MecanikProcessBreaker.MyConnect, T_MecanikProcessBreaker.MyConnectHook);
		MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "closesocket", (LPVOID)T_MecanikProcessBreaker.MyClosesocket, T_MecanikProcessBreaker.MyClosesocketHook);
		
		//MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "WSAAsyncSelect", (LPVOID)T_MecanikProcessBreaker.MyWSAAsyncSelect, T_MecanikProcessBreaker.MyWSAAsyncSelectHook);

		MecanikDetours::T_MNTDetours.RIPFunction("kernel32.dll", "OutputDebugStringW", (LPVOID)T_MecanikProcessBreaker.MyOutputDebugStringW, T_MecanikProcessBreaker.MyOutputDebugStringWHook);
		MecanikDetours::T_MNTDetours.RIPFunction("kernel32.dll", "OutputDebugStringA", (LPVOID)T_MecanikProcessBreaker.MyOutputDebugStringA, T_MecanikProcessBreaker.MyOutputDebugStringAHook);
		MecanikDetours::T_MNTDetours.RIPFunction("kernel32.dll", "QueryPerformanceCounter", (LPVOID)T_MecanikProcessBreaker.MyQueryPerformanceCounter, T_MecanikProcessBreaker.MyQueryPerformanceCounterHook);
		MecanikDetours::T_MNTDetours.RIPFunction("kernel32.dll", "QueryPerformanceFrequency", (LPVOID)T_MecanikProcessBreaker.MyQueryPerformanceFrequency, T_MecanikProcessBreaker.MyQueryPerformanceFrequencyHook);

	}

	int __stdcall MecanikProcessBreaker::MyWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
	{
		EnterCriticalSection(&T_MecanikProcessBreaker.MyWSASend_Critical);
		MecanikDetours::T_MNTDetours.UNRIPFunction("ws2_32.dll", "WSASend", T_MecanikProcessBreaker.MyWSASendHook);

		int result = WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);

		// WE CAN DO ANYTHING WE WANT HERE LOL :)
		M_Console.ConsoleOutput(6, "[MyWSASend] :: (0x%02hX 0x%02hX 0x%02hX 0x%02hX 0x%02hX 0x%02hX)", lpBuffers->buf[0], lpBuffers->buf[1], lpBuffers->buf[2], lpBuffers->buf[3], lpBuffers->buf[4]);

		MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "WSAsend", T_MecanikProcessBreaker.MyWSASend, T_MecanikProcessBreaker.MyWSASendHook);
		LeaveCriticalSection(&T_MecanikProcessBreaker.MyWSASend_Critical);
		return result;
	}

	int __stdcall MecanikProcessBreaker::MyWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED  lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
	{
		EnterCriticalSection(&T_MecanikProcessBreaker.MyWSARecv_Critical);
		MecanikDetours::T_MNTDetours.UNRIPFunction("ws2_32.dll", "WSARecv", T_MecanikProcessBreaker.MyWSARecvHook);

		int result = WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);

		// WE CAN DO ANYTHING WE WANT HERE LOL :)
		M_Console.ConsoleOutput(6, "[MyWSARecv] :: (0x%02hX 0x%02hX 0x%02hX 0x%02hX 0x%02hX 0x%02hX)", lpBuffers->buf[0], lpBuffers->buf[1], lpBuffers->buf[2], lpBuffers->buf[3], lpBuffers->buf[4]);

		MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "WSARecv", T_MecanikProcessBreaker.MyWSARecv, T_MecanikProcessBreaker.MyWSARecvHook);
		LeaveCriticalSection(&T_MecanikProcessBreaker.MyWSARecv_Critical);
		return result;
	}

	int __stdcall MecanikProcessBreaker::MySend(SOCKET s, const char *buf, int len, int flags)
	{
		EnterCriticalSection(&T_MecanikProcessBreaker.MySend_Critical);
		MecanikDetours::T_MNTDetours.UNRIPFunction("ws2_32.dll", "send", T_MecanikProcessBreaker.MySendHook);

		int result = send(s, buf, len, flags);

		// WE CAN DO ANYTHING WE WANT HERE LOL :)
		M_Console.ConsoleOutput(4, "[MySend] :: (0x%02hX 0x%02hX 0x%02hX 0x%02hX 0x%02hX 0x%02hX)", buf[0], buf[1], buf[2], buf[3], buf[4]);

		MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "send", T_MecanikProcessBreaker.MySend, T_MecanikProcessBreaker.MySendHook);
		LeaveCriticalSection(&T_MecanikProcessBreaker.MySend_Critical);
		return result;
	}

	int __stdcall MecanikProcessBreaker::MyRecv(SOCKET s, char *buf, int len, int flags)
	{
		EnterCriticalSection(&T_MecanikProcessBreaker.MyRecv_Critical);
		MecanikDetours::T_MNTDetours.UNRIPFunction("ws2_32.dll", "recv", T_MecanikProcessBreaker.MyRecvHook);

		int result = recv(s, buf, len, flags);

		// WE CAN DO ANYTHING WE WANT HERE LOL :)
		M_Console.ConsoleOutput(4, "[MyRecv] :: (0x%02hX 0x%02hX 0x%02hX 0x%02hX 0x%02hX 0x%02hX)", buf[0], buf[1], buf[2], buf[3], buf[4]);

		MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "recv", T_MecanikProcessBreaker.MyRecv, T_MecanikProcessBreaker.MyRecvHook);
		LeaveCriticalSection(&T_MecanikProcessBreaker.MyRecv_Critical);
		return result;
	}

	int __stdcall MecanikProcessBreaker::MyConnect(SOCKET s, const struct sockaddr *name, int namelen)
	{
		EnterCriticalSection(&T_MecanikProcessBreaker.MyConnect_Critical);
		MecanikDetours::T_MNTDetours.UNRIPFunction("ws2_32.dll", "connect", T_MecanikProcessBreaker.MyConnectHook);

		SOCKADDR_IN* name_in = (SOCKADDR_IN*)name;
		unsigned short Port = ntohs(name_in->sin_port);
		char *IP = inet_ntoa(name_in->sin_addr);

		int result = connect(s, name, namelen);

		// WE CAN DO ANYTHING WE WANT HERE LOL :)
		M_Console.ConsoleOutput(3, "[MyConnect] :: (%s : %d)", IP, Port);

		MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "connect", T_MecanikProcessBreaker.MyConnect, T_MecanikProcessBreaker.MyConnectHook);
		LeaveCriticalSection(&T_MecanikProcessBreaker.MyConnect_Critical);
		return result;
	}

	int __stdcall MecanikProcessBreaker::MyClosesocket(SOCKET s)
	{
		EnterCriticalSection(&T_MecanikProcessBreaker.MyClosesocket_Critical);
		MecanikDetours::T_MNTDetours.UNRIPFunction("ws2_32.dll", "closesocket", T_MecanikProcessBreaker.MyClosesocketHook);

		SOCKADDR_IN* name_in = (SOCKADDR_IN*)s;
		char *IP = inet_ntoa(name_in->sin_addr);

		int result = closesocket(s);

		// WE CAN DO ANYTHING WE WANT HERE LOL :)
		M_Console.ConsoleOutput(5, "[MyClosesocket] :: (%s)", IP);

		MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "closesocket", T_MecanikProcessBreaker.MyClosesocket, T_MecanikProcessBreaker.MyClosesocketHook);
		LeaveCriticalSection(&T_MecanikProcessBreaker.MyClosesocket_Critical);
		return result;
	}

	int __stdcall MecanikProcessBreaker::MyWSAAsyncSelect(SOCKET s, HWND hWnd, unsigned int wMsg, long lEvent)
	{
		EnterCriticalSection(&T_MecanikProcessBreaker.MyWSAAsyncSelect_Critical);
		MecanikDetours::T_MNTDetours.UNRIPFunction("ws2_32.dll", "WSAAsyncSelect", T_MecanikProcessBreaker.MyWSAAsyncSelectHook);

		SOCKADDR_IN* name_in = (SOCKADDR_IN*)s;
		char *IP = inet_ntoa(name_in->sin_addr);

		int result = WSAAsyncSelect(s, hWnd, wMsg, lEvent);

		// WE CAN DO ANYTHING WE WANT HERE LOL :)
		M_Console.ConsoleOutput(5, "[MyWSAAsyncSelect] :: (%s)", IP);

		MecanikDetours::T_MNTDetours.RIPFunction("ws2_32.dll", "WSAAsyncSelect", T_MecanikProcessBreaker.MyWSAAsyncSelect, T_MecanikProcessBreaker.MyWSAAsyncSelectHook);
		LeaveCriticalSection(&T_MecanikProcessBreaker.MyWSAAsyncSelect_Critical);
		return result;
	}

	void __stdcall MecanikProcessBreaker::MyOutputDebugStringW(LPCSTR lpOutput)
	{
		EnterCriticalSection(&T_MecanikProcessBreaker.OutputDebugStringW_Critical);
		MecanikDetours::T_MNTDetours.UNRIPFunction("kernel32.dll", "OutputDebugStringW", T_MecanikProcessBreaker.MyOutputDebugStringWHook);

		// WE CAN DO ANYTHING WE WANT HERE LOL :)
		M_Console.ConsoleOutput(5, "[MyOutputDebugStringW] :: %s", lpOutput);

		MecanikDetours::T_MNTDetours.RIPFunction("kernel32.dll", "OutputDebugStringW", (LPVOID)T_MecanikProcessBreaker.MyOutputDebugStringW, T_MecanikProcessBreaker.MyOutputDebugStringWHook);
		LeaveCriticalSection(&T_MecanikProcessBreaker.OutputDebugStringW_Critical);
	}

	void __stdcall MecanikProcessBreaker::MyOutputDebugStringA(LPCSTR lpOutput)
	{
		EnterCriticalSection(&T_MecanikProcessBreaker.OutputDebugStringA_Critical);
		MecanikDetours::T_MNTDetours.UNRIPFunction("kernel32.dll", "OutputDebugStringA", T_MecanikProcessBreaker.MyOutputDebugStringAHook);

		// WE CAN DO ANYTHING WE WANT HERE LOL :)
		M_Console.ConsoleOutput(5, "[MyOutputDebugStringA] :: %s", lpOutput);

		MecanikDetours::T_MNTDetours.RIPFunction("kernel32.dll", "OutputDebugStringA", (LPVOID)T_MecanikProcessBreaker.MyOutputDebugStringA, T_MecanikProcessBreaker.MyOutputDebugStringAHook);
		LeaveCriticalSection(&T_MecanikProcessBreaker.OutputDebugStringA_Critical);
	}

	BOOL WINAPI MecanikProcessBreaker::MyQueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)
	{
		EnterCriticalSection(&T_MecanikProcessBreaker.MyQueryPerformanceCounter_Critical);
		MecanikDetours::T_MNTDetours.UNRIPFunction("kernel32.dll", "QueryPerformanceCounter", T_MecanikProcessBreaker.MyQueryPerformanceCounterHook);

		// WE CAN DO ANYTHING WE WANT HERE LOL :)
		//M_Console.ConsoleOutput(3, "[MyQueryPerformanceCounter] ::  %f", lpPerformanceCount);

		MecanikDetours::T_MNTDetours.RIPFunction("kernel32.dll", "QueryPerformanceCounter", (LPVOID)T_MecanikProcessBreaker.MyQueryPerformanceCounter, T_MecanikProcessBreaker.MyQueryPerformanceCounterHook);
		LeaveCriticalSection(&T_MecanikProcessBreaker.MyQueryPerformanceCounter_Critical);

		return 0;
	}

	BOOL WINAPI MecanikProcessBreaker::MyQueryPerformanceFrequency(LARGE_INTEGER *lpPerformanceCount)
	{
		EnterCriticalSection(&T_MecanikProcessBreaker.MyQueryPerformanceFrequency_Critical);
		MecanikDetours::T_MNTDetours.UNRIPFunction("kernel32.dll", "QueryPerformanceFrequency", T_MecanikProcessBreaker.MyQueryPerformanceFrequencyHook);

		// WE CAN DO ANYTHING WE WANT HERE LOL :)
		//M_Console.ConsoleOutput(3, "[MyQueryPerformanceFrequency] :: %f", lpPerformanceCount);

		MecanikDetours::T_MNTDetours.RIPFunction("kernel32.dll", "QueryPerformanceFrequency", (LPVOID)T_MecanikProcessBreaker.MyQueryPerformanceFrequency, T_MecanikProcessBreaker.MyQueryPerformanceFrequencyHook);
		LeaveCriticalSection(&T_MecanikProcessBreaker.MyQueryPerformanceFrequency_Critical);
		return 0;
	}

}