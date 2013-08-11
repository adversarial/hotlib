#pragma once

#ifdef _DLL
	#define BUILDING_AS_LIB		TRUE
#else
	#define BUILDING_AS_LIB		FALSE	// disabled if building as standalone executable
#endif

#define BUILD_OP_USE_SEH	TRUE