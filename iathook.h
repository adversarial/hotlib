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

#include "hotlib.h"

#pragma region Prototypes
	void* STDCALL EXPORT hlSetIATHook32(IN const void* pModule, IN const char* pszLibraryName, IN const char* pszFunctionName, IN const PTR Detour, OUT HOOK32_T* Trampoline);
	void* STDCALL EXPORT hlRemoveIATHook32(INOUT HOOK32_T* Hook);
#pragma endregion