#include "hotlib.h"

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
							OUT TRAMPOLINE_T* Trampoline) {
    PTR    pDelta,
                pHotPatch;
    DWORD        dwProt;

	if (Trampoline->bEnabled)
		return NULL;
    Trampoline->pFunction = (void*)Function;
    Trampoline->pDetour = (void*)Detour;
    pHotPatch = (PTR)Trampoline->pFunction - 5;
    pDelta = (PTR)Trampoline->pDetour - pHotPatch - 5;    // dest - source - sizeof(jmp rel32)
    if(!VirtualProtect((LPVOID)pHotPatch, HOTPATCHSIZE, PAGE_EXECUTE_READWRITE, &dwProt))
            return NULL;
  #if BUILD_OP_USE_SEH
    __try {
  #endif
        CopyMemory(Trampoline->OriginalPre, (const void*)pHotPatch, HOTPATCHSIZE);
        *(BYTE*)pHotPatch++ = OpcodeJmp;            // jmp
        *(PTR*)pHotPatch = pDelta;           //     rel32
        pHotPatch += sizeof(PTR);
        *(WORD*)pHotPatch = *(WORD*)PrefixPatch;    // jmp -5
  #if BUILD_OP_USE_SEH
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
  #endif
    if(!VirtualProtect((LPVOID)((PTR)pHotPatch - 5), HOTPATCHSIZE, dwProt, &dwProt))
            return NULL;
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
void* STDCALL EXPORT hlRemoveHotPatch32(INOUT TRAMPOLINE_T* Trampoline) {
    PTR    pHotPatch;
    DWORD        dwProt;

	if (!Trampoline->bEnabled)
		return FALSE;
    pHotPatch = (PTR)Trampoline->pFunction - 5;
    if(!VirtualProtect((LPVOID)pHotPatch, 7, PAGE_EXECUTE_READWRITE, &dwProt))
            return NULL;
  #if BUILD_OP_USE_SEH
    __try {
  #endif
        memcpy((void*)pHotPatch, Trampoline->OriginalPre, HOTPATCHSIZE);
  #if BUILD_OP_USE_SEH
	} __except(EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
  #endif
    if(!VirtualProtect((LPVOID)((PTR)pHotPatch), HOTPATCHSIZE, dwProt, &dwProt))
            return NULL;
    memset(Trampoline, 0, sizeof(TRAMPOLINE_T));
    return (void*)((PTR)pHotPatch + 5);
}

/// <summary>
/// Checks if feature is available </summary>
/// 
/// <returns>
/// Returns 1 if available, 0 if unavailabe </returns>
int STDCALL hlIsFeatureCompatible(IN HOTLIB_FEATURE hlFeature) {
	switch(hlFeature) {
		case HOTPATCH:
			return 1;
		default:
			return 0;
	}
}