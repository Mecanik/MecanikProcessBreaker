#pragma once
#include "Includes.hpp"
#include <cassert>
namespace VMTManager
{
	namespace Hooks
	{
		// Pasted here to make it a standalone lib
		typedef unsigned int uint;
		typedef int int_ptr;
		template< typename T > inline T make_ptr(void* ptr, int_ptr offset) { return reinterpret_cast<T>((size_t)ptr + offset); }
		inline void**& getvtable(void* inst, int_ptr offset = 0) { return *reinterpret_cast<void***>((size_t)inst + offset); }


		// Find the number of vfuncs in a vtable
		uint CountFuncs(void** pVMT);
		uint CountFuncs(void* begin, void* end, void** pVMT);

		// Find the index for a vfunc, result is negative if not found
		int FindFunc(void** pVMT, void* pFunc, uint vfuncs = 0);


		// ----------------------------------------------------------------
		// Class: VMTManager
		// ----------------------------------------------------------------
		// Hooks virtual functions by replacing the vtable pointer from an instance.
		//
		// Purpose:
		//  Manages the virtual table of an object.
		//
		class VMTManager
		{
			// Forbid copy constructing and assignment.
			VMTManager(const VMTManager&);
			VMTManager& operator= (const VMTManager&);

		public:
			VMTManager(void* inst, size_t offset = 0, uint vfuncs = 0);
			~VMTManager();

			// Hooks a function by index.
			inline void HookMethod(void* newfunc, size_t index)
			{
				assert(index < _vcount);
				_array[index + 3] = newfunc;
			}
			// Unhooks a function by index.
			inline void UnhookMethod(size_t index)
			{
				assert(index < _vcount);
				_array[index + 3] = _oldvmt[index];
			}

			// Manage the hooks.
			inline void Unhook() { *_vftable = _oldvmt; }
			inline void Rehook() { *_vftable = _array + 3; }
			inline bool Hooked() const { return *_vftable != _oldvmt; }
			inline void EraseHooks() { for (uint i = 0; i < _vcount; ++i) _array[i + 3] = _vftable[i]; }
			inline uint NumFuncs() const { return _vcount; }

			// If the instance is somehow destroyed before you get a chance to unhook it or destruct this hook object, call this.
			// It'll prevent the destructor from crashing.
			inline void Poof() { _vftable = 0; }

			// Get the original function.
			// Use a function prototype for the template argument to make it very easy to call this function.
			// Example syntax: hook.GetMethod<bool (__thiscall*)( void*, int )>( 12 )( inst, arg );
			template< typename Fn >
			inline Fn GetMethod(size_t index) const
			{
				assert(index < _vcount);
				return (Fn)_oldvmt[index];
			}

		protected:
			inline void _set_guard(size_t S) { _array[1] = (void*)S; }
			inline size_t _get_guard() const { return (size_t)_array[1]; }
			inline void _set_backptr(void* ptr) { _array[0] = ptr; }
			inline void* _get_backptr() const { return _array[0]; }

		private:
			void*** _vftable;
			void**  _oldvmt;
			void**  _array;
			uint    _vcount;
		};
	};
}