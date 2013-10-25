/*
 * Copyright (c) 2013 x8esix
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
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

#   pragma pack (push, 1)

        typedef struct {
            void    *pFunction,			// tsk tsk
                    *pBypass,			// call function around hook
                    *pDetour;			// your hook
            BYTE     bEnabled;			// not used currently (just T/F for outside, don't you use returns!?!)
            BYTE     OriginalPre[HOTPATCHSIZE];	// play nice with other people who hook
        } TRAMPOLINE32_T;

        typedef struct {
            void    *IatEntry,          // IAT item ptr
                    *pBypass,           // original function ptr
                    *pDetour;           // your hook
            BYTE     bEnabled;
        } HOOK32_T;

#   pragma pack(pop)

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