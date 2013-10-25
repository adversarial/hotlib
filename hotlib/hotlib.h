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

#include "build_op.h"
#include "types.h"

#include <Windows.h>
#include <stdlib.h>
#include <stdint.h>

#include "..\..\peel\doc\PEel_public.h"
#pragma comment(lib, "PEel")			// required for IAT and EAT hooks

#pragma region Constants
    static const BYTE PrefixPatch[] = {
        0xeb, 0xf9						// jmp -5, signed
    };

    static const BYTE OpcodeJmp = 0xe9;	// jmp rel32

#   define JMPREL32SIZE	    5			// e9 xx xx xx xx
#   define JMPREL64SIZE     9           // e9 xx xx xx xx xx xx xx xx
#   define JMPREL8SIZE		2			// eb xx

#   ifdef _M_IX86
#       define HOTPATCHSIZE    JMPREL32SIZE + JMPREL8SIZE
#   else
#       define HOTPATCHSIZE    JMPREL64SIZE + JMPREL8SIZE
#   endif

#   define NAKEDCALLPROLOG 0			// full retard

	const static char tzVersion[] = "hotlib \x03 \x03 by x8esix";
#pragma endregion

#pragma region TypesDefines
    #pragma pack(push)
    #pragma pack (1)
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
    #pragma pack(pop)

	typedef enum HOTLIB_FEATURE { 
		HOTPATCH,
        IATHOOK,
        EATHOOK
	} HOTLIB_FEATURE;
#pragma endregion

#pragma region Prototypes
	int STDCALL EXPORT hlIsFeatureAvailable(IN HOTLIB_FEATURE hlFeature);
#pragma endregion

#define PROLOG NAKEDCALLPROLOG			// change for stdcall hook to change init, not really safe yet
// msvc dbg uses symbols as a list of jmps to allow for LTCG and function-level-linking
// function:
//    jmp real_function
// function2:
//    jmp real_function2
// etc                                            jmp [*0xdeadbeef*]                            [rel32]
#define MSVCFUNCTIONADDR(trampoline) ((*(PTR*)((PTR)trampoline + 1)) + (PTR)trampoline + PROLOG)

#include "hotpatch.h"
#include "iathook.h"