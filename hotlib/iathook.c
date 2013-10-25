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

#include "iathook.h"

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
void* STDCALL EXPORT hlSetIATHook32(IN const void* pModule, IN const char* pszLibraryName, IN const char* pszFunctionName, IN const PTR Detour, OUT HOOK32_T* Hook) {
    VIRTUAL_MODULE  vm = {0};
    IMPORT_LIBRARY* pIL = NULL;
    IMPORT_ITEM*    pII = NULL;

    DWORD dwProtect = 0;

    if (!LOGICAL_SUCCESS(PlAttachImage(pModule, &vm)))
        return NULL;
    PlEnumerateImports(&vm.PE);
    for (pIL = vm.PE.pImport; pIL != NULL; pIL = (IMPORT_LIBRARY*)pIL->Flink) {
        if (!strcmp(pIL->Library, pszLibraryName)) {
            for (pII = pIL->iiImportList; pII != NULL; pII = (IMPORT_ITEM*)pII->Flink) {
                if ((PTR32)pszFunctionName & IMAGE_ORDINAL_FLAG32 ? pII->Ordinal == pszFunctionName : !strcmp(pszFunctionName, pII->Name)) {
                    if(!VirtualProtect(pII->dwItemPtr, sizeof(PTR32), PAGE_READWRITE, &dwProtect)) {
                        PlFreeEnumeratedImports(&vm.PE);
                        return NULL;
                    }
#                 if BUILD_OP_USE_SEH
                    __try {
#                 endif
                        Hook->IatEntry = (void*)pII->dwItemPtr;
                        Hook->pBypass = (void*)*pII->dwItemPtr;
                        Hook->pDetour = (void*)Detour;
                        *pII->dwItemPtr = (PTR32)Detour;
#                 if BUILD_OP_USE_SEH
                    } __except(EXCEPTION_EXECUTE_HANDLER) {
                        return NULL;
                    }
#                 endif
                        VirtualProtect(pII->dwItemPtr, sizeof(PTR32), dwProtect, &dwProtect);
                        PlFreeEnumeratedImports(&vm.PE);
                        Hook->bEnabled = TRUE;
                        return Hook->pBypass;
                }
            }
        }
    }
    PlFreeEnumeratedImports(&vm.PE);
    return NULL;
}

/// <summary>
/// Places hotpatch overlay (restores previous patches) </summary>
///
/// <param name="Trampoline">
/// Struct with info about hook, will be cleared by function </param>
/// 
/// <returns>
/// Returns address of function that was hotpatched, NULL on error </returns>
void* STDCALL EXPORT hlRemoveIATHook32(INOUT HOOK32_T* Hook) {
    DWORD dwProtect = 0;
    void *pIatEntry = NULL;

    if (!Hook->bEnabled)
        return NULL;
    if(!VirtualProtect(Hook->IatEntry, sizeof(PTR32), PAGE_READWRITE, &dwProtect))
        return NULL;

#   if BUILD_OP_USE_SEH
    __try {
#   endif
        
        *(PTR32*)Hook->IatEntry = (PTR32)Hook->pBypass;

#   if BUILD_OP_USE_SEH
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
#   endif

    VirtualProtect(Hook->IatEntry, sizeof(PTR32), PAGE_READWRITE, &dwProtect);
    pIatEntry = Hook->IatEntry;
    memset(Hook, 0, sizeof(HOOK32_T));
    return pIatEntry;
}