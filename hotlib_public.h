/*
 * (C) Copyright 2013 x8esix.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 3.0 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-3.0.txt
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 */

#pragma once

// public header for hotlib 0.1
// hotlib is an opensource, mid level wrapper for hooking functions.
// currently, only hotpatching is supported.
// released under LGPL3.0
// by x8esix

// Usage: include "hotlib_public.h" in project and link to hotlib.lib

#ifndef uint8_t
	#ifdef __cplusplus
		#include <cstdint>
	#else
		#include <stdint.h>
	#endif
#endif

#pragma region TypesDefines
	typedef uint8_t BYTE;
    typedef uint32_t PTR32;
	typedef uint64_t PTR64;

#   define JMPREL32SIZE	    5			// e9 xx xx xx xx
#   define JMPREL64SIZE     9           // e9 xx xx xx xx xx xx xx xx
#   define JMPREL8SIZE		2			// eb xx

#   ifdef _M_IX86
        typedef PTR32 PTR;
#       define HOTPATCHSIZE    JMPREL32SIZE + JMPREL8SIZE
#   else
#       error hotlib is Not x64 Compatible!
        typedef PTR64 PTR;
#       define HOTPATCHSIZE    JMPREL64SIZE + JMPREL8SIZE
#   endif

#   define IN                       // usually const
#   define OUT                      // ptr target will be modified
#   define INOUT                    // ptr target will be needed then modified

#   define STDCALL __stdcall

#   pragma pack(push)
#   pragma pack (1)
        struct _TRAMPOLINE_T32 {
            void    *pFunction,			// pointer to function
                    *pBypass,			// call function around hook
                    *pDetour;			// your detour
            BYTE    OriginalPre[HOTPATCHSIZE];		// play nice with other people who hook
            BYTE    bEnabled;			// member functions will check this
        };
#   pragma pack(pop)
	typedef _TRAMPOLINE_T32 TRAMPOLINE_T;

	enum HOTLIB_FEATURE { 
		HOTPATCH,
		IATHOOK
	};
#pragma endregion

#pragma region Prototypes
#ifdef __cplusplus
extern "C" {
#endif
    /// <summary>
	/// Checks if feature is available </summary>
	/// 
	/// <returns>
	/// Returns 1 if available, 0 if unavailabe </returns>
	int STDCALL hlIsFeatureCompatible(IN HOTLIB_FEATURE hlFeature);

	/// <summary>
	/// Places hotpatch overlay (saves previous patches and restores on removal) </summary>
	///
	/// <param name="Function">
	/// Target function to be hotpatched (no error checking) </param>
	/// <param name="Detour">
	/// Trampoline that function will detour to </param>
	/// <param name="Trampoline">
	/// Struct to recieve info about hook </param>
	/// 
	/// <returns>
	/// Returns address of bypass for hooked function (Trampoline->pBypass), NULL on error </returns>
    void* STDCALL hlSetHotPatch32(IN const PTR Function, IN const PTR Detour, OUT TRAMPOLINE_T* Trampoline);

	/// <summary>
	/// Places hotpatch overlay (restores previous patches) </summary>
	///
	/// <param name="Trampoline">
	/// Struct with info about hook, will be cleared by function </param>
	/// 
	/// <returns>
	/// Returns address of function that was hotpatched, NULL on error </returns>
    void* STDCALL hlRemoveHotPatch32(INOUT TRAMPOLINE_T* Trampoline);

    /// <summary>
    /// Replaces IAT entry and saves old one in pBypass </summary>
    ///
    /// <param name="pModule">
    /// Pointer to module base </param>
    /// <param name="pszLibraryName">
    /// Library that function belongs to </param>
    /// <param name="pszFunctionName">
    /// Target function to be hooked </param>
    /// <param name="Detour">
    /// Trampoline that function will detour to </param>
    /// <param name="Trampoline">
    /// Struct to recieve info about hook </param>
    /// 
    /// <returns>
    /// Returns address of bypass for hooked function (Trampoline->pBypass), NULL on error </returns>
    void* STDCALL hlSetIATHook32(IN const void* pModule, IN const char* pszLibraryName, IN const char* pszFunctionName, IN const PTR Detour, OUT HOOK32_T* Trampoline);
	
    /// <summary>
    /// Places hotpatch overlay (restores previous patches) </summary>
    ///
    /// <param name="Trampoline">
    /// Struct with info about hook, will be cleared by function </param>
    /// 
    /// <returns>
    /// Returns address of function that was hotpatched, NULL on error </returns>
    void* STDCALL hlRemoveIATHook32(INOUT HOOK32_T* Hook);
#ifdef __cplusplus
};
#endif
#pragma endregion