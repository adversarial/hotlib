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
	void* STDCALL EXPORT hlSetHotPatch32(IN const PTR Function, IN const PTR Detour, OUT TRAMPOLINE_T* Trampoline);
	void* STDCALL EXPORT hlRemoveHotPatch32(INOUT TRAMPOLINE_T* Trampoline);
#pragma endregion