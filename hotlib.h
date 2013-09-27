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

#include "build_op.h"
#include "types.h"

#include <Windows.h>
#include <stdlib.h>
#include <stdint.h>

#include "..\peel\doc\PEel_public.h"
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