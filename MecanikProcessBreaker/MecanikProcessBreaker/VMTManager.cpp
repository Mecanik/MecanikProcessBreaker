#include "stdafx.h"
#include "VMTManager.h"

namespace VMTManager
{
	namespace Hooks
	{
		uint CountFuncs(void** vmt)
		{

			MEMORY_BASIC_INFORMATION mem;
			int i = -1;
			do { i++; VirtualQuery(vmt[i], &mem, sizeof(MEMORY_BASIC_INFORMATION)); } while (mem.Protect == PAGE_EXECUTE_READ || mem.Protect == PAGE_EXECUTE_READWRITE);
			return i;
		}

		uint CountFuncs(void* begin, void* end, void** vmt)
		{
			int i = -1;
			do i++; while (begin < vmt[i] && vmt[i] < end);
			return i;
		}
		int FindFunc(void** vmt, void* func, uint vfuncs)
		{
			if (!vfuncs) vfuncs = CountFuncs(vmt);
			for (uint i = 0; i < vfuncs; i++)
			{
				if (vmt[i] == func) return i;
			}
			return -1;
		}

		// VMTManager
		VMTManager::VMTManager(void* inst, size_t offset, uint vfuncs)
		{
			_vftable = make_ptr<void***>(inst, offset);
			_oldvmt = *_vftable;
			// Count vfuncs ourself if needed
			if (!vfuncs) vfuncs = CountFuncs(_oldvmt);
			_vcount = vfuncs;
			// Allocate room for the new vtable
			_array = (void**)malloc((vfuncs + 3) * sizeof(void*));
			// Initialize RTTI pointer (should there be one)
			_array[2] = _oldvmt[-1];
			// Copy over the other vfuncs
			for (uint i = 0; i < vfuncs; ++i) _array[i + 3] = _oldvmt[i];
			// Hook it
			*_vftable = _array + 3;
		}
		VMTManager::~VMTManager()
		{
			if (_vftable) Unhook();
			free(_array);
		}
	}
}