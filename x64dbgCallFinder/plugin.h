#pragma once

#include "pluginmain.h"
#include <Windows.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <commctrl.h>
#include <thread>
#include "resource.h"
#include <psapi.h>
#include <sstream>
#include <windowsx.h>

//#include "TitanEngine/TitanEngine.h"

using namespace Script::Module;
using namespace Script::Symbol;
using namespace Script::Debug;
using namespace Script::Register;

#define PAGE_SHIFT              (12)
//#define PAGE_SIZE               (4096)
#define PAGE_ALIGN(Va)          ((ULONG_PTR)((ULONG_PTR)(Va) & ~(PAGE_SIZE - 1)))
#define BYTES_TO_PAGES(Size)    (((Size) >> PAGE_SHIFT) + (((Size) & (PAGE_SIZE - 1)) != 0))
#define ROUND_TO_PAGES(Size)    (((ULONG_PTR)(Size) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

#define MENU_MAINWINDOW_POPUP 0
#define MENU_ABOUT_POPUP 1

//functions
bool pluginInit(PLUG_INITSTRUCT* initStruct);
void pluginStop();
void pluginSetup();

struct LIBRARY_ITEM_DATA_EXTEND
{
	LPVOID BaseOfDll;
	DWORD Size;
	LPVOID Oep;
	char szLibraryName[MAX_PATH];
};





