#ifndef __PEUtil_H
#define __PEUtil_H

#pragma once


#define MakePtr(Type, Base, Offset) ((Type)(DWORD_PTR(Base) + (DWORD_PTR)(Offset)))


/**
 * \brief 
 */
class CPEUtil
{
public:
	/**
	 * \brief 
	 */
	static BOOL GetFunctionPtrFromIAT(void* pDosHdr, LPCSTR pImportModuleName, LPCSTR pFunctionSymbol, PVOID* ppvFn)
	{
		if (!ppvFn || !pDosHdr || !pImportModuleName || !pFunctionSymbol
				|| pImportModuleName[0] == 0 || pFunctionSymbol[0] == 0)
		{
			return FALSE;
		}

		*ppvFn = 0;


		PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pDosHdr;
		PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, pDOSHeader, pDOSHeader->e_lfanew);
		PIMAGE_IMPORT_DESCRIPTOR pImportDesc = MakePtr(PIMAGE_IMPORT_DESCRIPTOR, pDOSHeader, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		if (IsBadReadPtr(pDOSHeader, sizeof(PIMAGE_DOS_HEADER))
				|| pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE
				|| pNTHeader->Signature != IMAGE_NT_SIGNATURE
				|| pImportDesc == (PIMAGE_IMPORT_DESCRIPTOR)pNTHeader)
		{
			return FALSE;
		}

		while (pImportDesc->Name)
		{
			LPCSTR pszDllName = MakePtr(LPCSTR, pDOSHeader, pImportDesc->Name);

			if (_stricmp(pszDllName, pImportModuleName) == 0)
			{
				PIMAGE_THUNK_DATA pThunk = MakePtr(PIMAGE_THUNK_DATA, pDOSHeader, pImportDesc->FirstThunk);
				PIMAGE_THUNK_DATA pThunk1 = MakePtr(PIMAGE_THUNK_DATA, pDOSHeader, pImportDesc->OriginalFirstThunk);
				int idx = 0;

				while (pThunk[idx].u1.Function) 
				{
					const char* pszProcName = 0;

					if ((pThunk1[idx].u1.AddressOfData & 0x80000000) != 0)
					{
						pszProcName = GetFnNameByOrdinal(pImportModuleName, pThunk1[idx].u1.AddressOfData & 0x7FFFFFFF);
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME pImgData = MakePtr(PIMAGE_IMPORT_BY_NAME, pDOSHeader, pThunk1[idx].u1.AddressOfData);
						pszProcName = (char*)pImgData->Name;
					}

					if (pszProcName && _stricmp(pszProcName, pFunctionSymbol) == 0)
					{
						*ppvFn = ULongToPtr(pThunk[idx].u1.Function);
						return TRUE;
					}

					idx++;
				}
			}

			pImportDesc++;
		}

		return FALSE;
	}



	/**
	 * \brief 
	 */
	static const char* GetFnNameByOrdinal(LPCSTR pImportModuleName, DWORD dwOrd)
	{
		PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)GetModuleHandleA(pImportModuleName);
		PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, pDOSHeader, pDOSHeader->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY pExportDir = MakePtr(PIMAGE_EXPORT_DIRECTORY, pDOSHeader, pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		if (!pDOSHeader 
				|| IsBadReadPtr(pDOSHeader, sizeof(PIMAGE_DOS_HEADER))
				|| pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE
				|| pNTHeader->Signature != IMAGE_NT_SIGNATURE
				|| pExportDir == (PIMAGE_EXPORT_DIRECTORY)pNTHeader)
		{
			return 0;
		}

		LPDWORD pNames = MakePtr(LPDWORD, pDOSHeader, pExportDir->AddressOfNames);
		LPWORD pOrdNames = MakePtr(LPWORD, pDOSHeader, pExportDir->AddressOfNameOrdinals);

		for (int i=0; i < (int)pExportDir->NumberOfNames; i++)
		{
			DWORD dwFoundOrd = pOrdNames[i] + pExportDir->Base;

			if (dwFoundOrd == dwOrd)
			{
				const char* pszName = (char*)MakePtr(char*, pDOSHeader, pNames[i]);
				return pszName;
			}
		}

		return 0;
	}
};


#endif //__PEUtil_H