#pragma once

#include <stdint.h>

#pragma region TypesDefines
    typedef uint8_t BYTE;
    typedef uint32_t PTR32;
	typedef uint64_t PTR64;

    #ifdef _M_IX86
        typedef PTR32 PTR;
    #else
        typedef PTR64 PTR;        // not x64 compatible
    #endif

    #define IN                       // usually const
    #define OUT                      // ptr content will be modified
    #define INOUT                    // ptr content will be needed then modified

    #if BUILDING_AS_LIB
        #define EXPORT __declspec(dllexport)// who doesn't use msvc?
    #else
        #define EXPORT
    #endif
    #define STDCALL __stdcall            // we do!
#pragma endregion