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
#include "HideModule.h"

void HideModule(HMODULE module)
{
	DWORD *PEB = NULL;
	DWORD *Ldr = NULL;
	DWORD *Flink = NULL;
	DWORD *p = NULL;
	DWORD *BaseAddress = NULL;
	DWORD *FullDllName = NULL;

	//Localization of PEB
	__asm
	{
		//The location of the FS save TEB
		//fs:[0x30]The location to save the PEB
		mov eax, fs:[0x30]
		mov PEB, eax
	}

	HMODULE hMod = module;

	//Get LDR
	Ldr = *((DWORD **)((unsigned char *)PEB + 0x0c));
	//The second list
	Flink = *((DWORD **)((unsigned char *)Ldr + 0x0c));
	p = Flink;

	do
	{
		BaseAddress = *((DWORD **)((unsigned char *)p + 0x18));
		FullDllName = *((DWORD **)((unsigned char *)p + 0x28));

		if ((DWORD*)hMod == BaseAddress)
		{
			**((DWORD **)(p + 1)) = (DWORD)*((DWORD **)p);
			*(*((DWORD **)p) + 1) = (DWORD)*((DWORD **)(p + 1));
			break;
		}

		p = *((DWORD **)p);
	} while (Flink != p);

	Flink = *((DWORD **)((unsigned char *)Ldr + 0x14));
	p = Flink;
	do
	{
		BaseAddress = *((DWORD **)((unsigned char *)p + 0x10));
		FullDllName = *((DWORD **)((unsigned char *)p + 0x20));
		if (BaseAddress == (DWORD *)hMod)
		{
			**((DWORD **)(p + 1)) = (DWORD)*((DWORD **)p);
			*(*((DWORD **)p) + 1) = (DWORD)*((DWORD **)(p + 1));
			break;
		}
		p = *((DWORD **)p);
	} while (Flink != p);

	Flink = *((DWORD **)((unsigned char *)Ldr + 0x1c));
	p = Flink;
	do
	{
		BaseAddress = *((DWORD **)((unsigned char *)p + 0x8));
		FullDllName = *((DWORD **)((unsigned char *)p + 0x18));
		if (BaseAddress == (DWORD *)hMod)
		{
			**((DWORD **)(p + 1)) = (DWORD)*((DWORD **)p);
			*(*((DWORD **)p) + 1) = (DWORD)*((DWORD **)(p + 1));
			break;
		}
		p = *((DWORD **)p);
	} while (Flink != p);
}

