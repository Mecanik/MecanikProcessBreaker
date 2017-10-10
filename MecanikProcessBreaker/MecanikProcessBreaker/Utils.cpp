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
#include "Utils.h"

//This function works like GetProcAddress 
//This function is useful in the event that GetProcAddress is not imported
//or when you are concerned it may be hooked
FARPROC GetProcedureAddress(HANDLE hModule, char* pszProcName)
{
	IMAGE_DOS_HEADER* pdhDosHeader = (IMAGE_DOS_HEADER*)hModule;
	//Check if valid PE
	if (pdhDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

	IMAGE_NT_HEADERS* pndNTHeader = (IMAGE_NT_HEADERS*)(pdhDosHeader->e_lfanew + (long)hModule);
	if (pndNTHeader->Signature != IMAGE_NT_SIGNATURE) return 0;

	//Traverse the export table to see if we can find the export
	IMAGE_EXPORT_DIRECTORY* iedExports = (IMAGE_EXPORT_DIRECTORY*)(pndNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (long)hModule);
	long* pNames = (long*)(iedExports->AddressOfNames + (long)hModule);
	short wOrdinalIndex = -1;
	for (int i = 0; i < iedExports->NumberOfFunctions; i++)
	{
		char* pszFunctionName = (char *)(pNames[i] + (long)hModule);

		if (lstrcmpi(pszFunctionName, pszProcName) == 0)
		{
			wOrdinalIndex = i;
			break;
		}
	}

	if (wOrdinalIndex == -1) return 0;

	//wIndex now holds the index of the function name in the names array, which is the index of the ordinal.
	//The ordinal also acts as the index of the address
	short* pOrdinals = (short*)(iedExports->AddressOfNameOrdinals + (long)hModule);
	unsigned long* pAddresses = (unsigned long*)(iedExports->AddressOfFunctions + (long)hModule);

	short wAddressIndex = pOrdinals[wOrdinalIndex];
	return (FARPROC)(pAddresses[wAddressIndex] + (long)hModule);
}