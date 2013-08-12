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