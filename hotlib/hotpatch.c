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

#include "hotpatch.h"

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
void* STDCALL EXPORT hlSetHotPatch32(IN const PTR Function,
							IN const PTR Detour,
							OUT TRAMPOLINE32_T* Trampoline) {
    PTR         pDelta,
                pHotPatch,
                pInstr;
    DWORD        dwProt;

	if (Trampoline->bEnabled)
		return NULL;
    Trampoline->pFunction = (void*)Function;
    Trampoline->pDetour = (void*)Detour;
    pHotPatch = (PTR)Trampoline->pFunction - 5;
    pInstr = pHotPatch;
    pDelta = (PTR)Trampoline->pDetour - pHotPatch - 5;    // dest - source - sizeof(jmp rel32)
    if(!VirtualProtect((LPVOID)pHotPatch, 7, PAGE_EXECUTE_READWRITE, &dwProt))
            return NULL;
#  if BUILD_OP_USE_SEH
    __try {
#  endif
        CopyMemory(Trampoline->OriginalPre, (const void*)pHotPatch, 7);
        *(BYTE*)pHotPatch++ = OpcodeJmp;            // jmp
        *(PTR*)pHotPatch = pDelta;                  //     rel32
        pHotPatch += sizeof(PTR);
        *(WORD*)pHotPatch = *(WORD*)PrefixPatch;    // jmp -5
#  if BUILD_OP_USE_SEH
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
#  endif
    if(!VirtualProtect((LPVOID)((PTR)pHotPatch - 5), 7, dwProt, &dwProt))
            return NULL;
    FlushInstructionCache(GetCurrentProcess(), (void*)pInstr, 7); // not necessary on x86 but whatever
    Trampoline->pBypass = (void*)((PTR)pHotPatch + sizeof(WORD));
    Trampoline->bEnabled = TRUE;
    return Trampoline->pBypass;
}

/// <summary>
/// Places hotpatch overlay (restores previous patches) </summary>
///
/// <param name="Trampoline">
/// Struct with info about hook, will be cleared by function </param>
/// 
/// <returns>
/// Returns address of function that was hotpatched, NULL on error </returns>
void* STDCALL EXPORT hlRemoveHotPatch32(INOUT TRAMPOLINE32_T* Trampoline) {
    PTR    pHotPatch,
           pInstr;
    DWORD        dwProt;

	if (!Trampoline->bEnabled)
		return FALSE;
    pHotPatch = (PTR)Trampoline->pFunction - 5;
    pInstr = pHotPatch;
    if(!VirtualProtect((LPVOID)pHotPatch, 7, PAGE_EXECUTE_READWRITE, &dwProt))
            return NULL;
#  if BUILD_OP_USE_SEH
    __try {
#  endif
        memcpy((void*)pHotPatch, Trampoline->OriginalPre, 7);
#  if BUILD_OP_USE_SEH
	} __except(EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
#  endif
    if(!VirtualProtect((LPVOID)((PTR)pHotPatch), 7, dwProt, &dwProt))
            return NULL;
    FlushInstructionCache(GetCurrentProcess(), (void*)pInstr, 7); // not necessary on x86 but whatever
    memset(Trampoline, 0, sizeof(TRAMPOLINE32_T));
    return (void*)((PTR)pHotPatch + 5);
}
