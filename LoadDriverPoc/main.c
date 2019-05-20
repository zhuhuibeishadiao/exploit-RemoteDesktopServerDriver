#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include "termdd.h"

int wmain(int argc, WCHAR **argv)
{
	HRESULT ret;
		if (argc == 3) {
			if (!LoadDriver(argv[1], argv[2], 0)) {
				char buf[256];
				FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
					MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, 255, NULL);
				printf("Patch Failed: %s\n", buf);
				return 1;
			}
			ret = GetLastError();
			if (ret) {
				printf("Driver Error - %08x\n", GetLastError());
			}
			else {
				printf("Driver Loaded!\n");
			}
			return 0;
		}
		if (argc == 2) {
			if (UnloadDriver(argv[1], 0))
				printf("Driver Unloaded!\n");
			else
				printf("Error Unloading!\n");
		}
		else {
			printf("Usage:\n\n"
				"TOOL.exe DRIVER.sys DRIVER.sys - Load Driver!\n"
				"TOOL.exe DRIVER.sys - Unload Driver!\n"
			);
		}
	return 0;
}
