#pragma once

#include "build_op.h"
#include "types.h"

#include <Windows.h>
#include <stdlib.h>
#include <stdint.h>

//#pragma comment(lib, "PEel")			// required for IAT and EAT hooks (not supported in 0.1)

#pragma region Constants
    static const BYTE PrefixPatch[] = {
        0xeb, 0xf9						// jmp -5, signed
    };

    static const BYTE OpcodeJmp = 0xe9;	// jmp rel32

	#define JMPREL32SIZE	5			// e9 xx xx xx xx
	#define JMPREL8SIZE		2			// eb xx
    #define HOTPATCHSIZE    JMPREL32SIZE + JMPREL8SIZE

    #define NAKEDCALLPROLOG 0			// full retard

	const static char tzVersion[] = "hotlib \x03 \x03 by x8esix";
#pragma endregion

#pragma region TypesDefines
    #pragma pack(push)
    #pragma pack (1)
        typedef struct {
            void    *pFunction,			// tsk tsk
                    *pBypass,			// call function around hook
                    *pDetour;			// your hook
            BYTE    OriginalPre[HOTPATCHSIZE];	// play nice with other people who hook
            BYTE    bEnabled;			// not used currently (just T/F for outside, don't you use returns!?!)
        } TRAMPOLINE_T;
    #pragma pack(pop)

	typedef enum HOTLIB_FEATURE { 
		HOTPATCH
	} HOTLIB_FEATURE;
#pragma endregion

#pragma region Prototypes
    void* STDCALL EXPORT hlSetHotPatch32(IN const PTR Function, IN const PTR Detour, OUT TRAMPOLINE_T* Trampoline);
    void* STDCALL EXPORT hlRemoveHotPatch32(INOUT TRAMPOLINE_T* Trampoline);
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