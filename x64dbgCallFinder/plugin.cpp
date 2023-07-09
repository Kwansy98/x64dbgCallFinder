#include "plugin.h"

#ifdef _UNICODE
#error "USE ASCII CODE PAGE"
#endif

using namespace Script::Module;
using namespace Script::Symbol;
using namespace Script::Debug;
using namespace Script::Register;


void SystemBreakpointCallback(CBTYPE bType, void*callbackInfo);
void DetachCallback(CBTYPE bType, void*callbackInfo);

std::map<duint, int> g_functionCallCount;

duint g_oep = 0;
bool g_scanExeOnly = true; // only scan exe by default


//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
	
	_plugin_registercallback(g_pluginHandle, CB_SYSTEMBREAKPOINT, SystemBreakpointCallback);
	_plugin_registercallback(g_pluginHandle, CB_DETACH, DetachCallback);
	
	return true; //Return false to cancel loading the plugin.
}



// find all user defined functions in secific module, return number of functions found
int ScanFunctionOnModule(duint base, duint size)
{
	constexpr int cmdSize = 0x100;
	char cmd[cmdSize] = { 0 };

	PUCHAR startAddress = (PUCHAR)base;
	PUCHAR endAddress = (PUCHAR)base + size;
	PUCHAR addr = (PUCHAR)startAddress;
	addr = (PUCHAR)PAGE_ALIGN(addr);

	size_t originCnt = g_functionCallCount.size();

	while (addr < endAddress)
	{
		// if not code, then skip this page
		if (((ULONG_PTR)addr == PAGE_ALIGN(addr)))
		{
			sprintf_s(cmd, cmdSize, "mem.iscode(%p)", addr);
			if (!DbgEval(cmd))
			{
				addr = PUCHAR(addr + PAGE_SIZE);
				continue;
			}
		}

		unsigned char dest[2];
		if (DbgMemRead((duint)addr, dest, 2))
		{
			// seems like a call
			if (dest[0] == 0xE8 || (dest[0] == 0xFF && dest[1] == 0x15))
			{
				// get dst addr
				DISASM_INSTR di;
				DbgDisasmAt((duint)addr, &di);
				duint FuncAddr = di.arg[0].value;

				// dst addr is code
				sprintf_s(cmd, cmdSize, "mem.iscode(%p)", (PVOID)FuncAddr);
				if (DbgEval(cmd))
				{
					// is user function
					sprintf_s(cmd, cmdSize, "mod.user(%p)", (PVOID)FuncAddr);
					if (DbgEval(cmd))
					{
						// is it jmp to system module?
						sprintf_s(cmd, cmdSize, "dis.iscallsystem(%p)", (PVOID)FuncAddr);
						if (!DbgEval(cmd))
						{
							// we find a function
							g_functionCallCount[FuncAddr] = 0;
						}
					}
				}
			}
		}

		addr++;
	}
	return int(g_functionCallCount.size() - originCnt);
}

// find all user functions, store in global map
void FindAllUserFunctions()
{
	g_functionCallCount.clear();
	
	constexpr int cmdSize = 0x100;
	char cmd[cmdSize] = { 0 };

	// only scan main module
	if (g_scanExeOnly)
	{
		ModuleInfo mainModuleInfo;
		Script::Module::GetMainModuleInfo(&mainModuleInfo);
		int funcCnt = ScanFunctionOnModule(mainModuleInfo.base, mainModuleInfo.size);
		dprintf("%d functions found in %s\n", funcCnt, mainModuleInfo.name);
		return;
	}
	
	// get all user modules, exe and dll
	ListInfo listInfo;
	if (Script::Module::GetList(&listInfo))
	{
		for (int i = 0; i < listInfo.count; i++)
		{
			ModuleInfo *mInfo = &((ModuleInfo *)listInfo.data)[i];
			
			sprintf_s(cmd, cmdSize, "mod.user(%p)", (PVOID)mInfo->base);
			if (DbgEval(cmd))
			{
				// scan functions in module
				int funcCnt = ScanFunctionOnModule(mInfo->base, mInfo->size);
				dprintf("%d functions found in %s\n", funcCnt, mInfo->name);
			}
		}
		BridgeFree(listInfo.data);
	}
}

void SystemBreakpointCallback(CBTYPE bType, void*callbackInfo)
{
	g_oep = 0;
	Cmd("bc");
}

void DetachCallback(CBTYPE bType, void*callbackInfo)
{
}

HWND g_pluginDlg = 0;
HWND hButtonSearch;
HWND hButtonReset;
HWND hButtonNewSearch;
HWND hEditCallCount;
HWND hEditResult;
HWND hCheckExeOnly;

// just don't want to block x64dbg, but not work as expect
DWORD WINAPI SettingBreakPointThread(LPVOID)
{
	// Cmd

	SetWindowTextA(hEditResult, "setting break point...");

	//Script::Debug::Pause();

	Cmd("LogDisable");
	GuiUpdateDisable();
	GuiDisableLog();
	for (auto &item : g_functionCallCount)
	{
		constexpr int cmdSize = 0x100;
		char cmd[cmdSize];

		duint addr = item.first;
		sprintf_s(cmd, cmdSize, "bp %p", (PVOID)addr);
		Cmd(cmd);
		sprintf_s(cmd, cmdSize, "bpcnd %p,\"0\"", (PVOID)addr); // break if 0
		Cmd(cmd);
	}
	Cmd("LogEnable");
	GuiUpdateEnable(true);
	GuiEnableLog();
	//Script::Debug::Run();

	constexpr int outputSize = 0x100;
	char output[outputSize] = { 0 };
	sprintf_s(output, outputSize, "%Id user functions found\r\nsetting break points may block x64dbg window for a while\r\nstart record!\r\nclick new search button to reset call count", g_functionCallCount.size());
	SetWindowTextA(hEditResult, output);

	EnableWindow(hButtonSearch, TRUE);
	EnableWindow(hButtonReset, TRUE);
	EnableWindow(hButtonNewSearch, TRUE);
	EnableWindow(hEditCallCount, TRUE);
	EnableWindow(hEditResult, TRUE);
	EnableWindow(hCheckExeOnly, TRUE);
	UpdateWindow(g_hwndDlg);

	return 0;
}

INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		g_pluginDlg = hwndDlg;
		hButtonSearch = GetDlgItem(hwndDlg, IDC_BUTTON1);
		hButtonReset = GetDlgItem(hwndDlg, IDC_BUTTON2);
		hButtonNewSearch = GetDlgItem(hwndDlg, IDC_BUTTON3);
		hEditCallCount = GetDlgItem(hwndDlg, IDC_EDIT1);
		hEditResult = GetDlgItem(hwndDlg, IDC_EDIT2);
		hCheckExeOnly = GetDlgItem(hwndDlg, IDC_CHECK1);
		Button_SetCheck(hCheckExeOnly, BST_CHECKED); // only scan exe by default

		return TRUE;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDC_BUTTON1)
		{
			// search button click

			char buffer[256];
			GetWindowTextA(GetDlgItem(hwndDlg, IDC_EDIT1), buffer, 256);
			int count = 0;
			sscanf_s(buffer, "%d", &count);
			dprintf("searching functions of hit count %d\n", count);

			std::vector<duint> functionsLeft;
			BPMAP bplist;
			int bpCnt = DbgGetBpList(bp_normal, &bplist);
			if (bpCnt)
			{
				for (int i = 0; i < bpCnt; i++)
				{
					if (bplist.bp[i].hitCount == count)
					{
						g_functionCallCount[bplist.bp[i].addr] = bplist.bp[i].hitCount;
						functionsLeft.push_back(bplist.bp[i].addr);
					}
					else
					{
						g_functionCallCount[bplist.bp[i].addr] = -1; // -1 means this function we dont interest in
					}
				}
				BridgeFree(bplist.bp);
			}
			SetWindowTextA(hEditResult, "");
			if (functionsLeft.size() > 100)
			{
				constexpr int bufferSize = 0x100;
				sprintf_s(buffer, bufferSize, "%Id functions left\r\ntoo many function found, result will not show", functionsLeft.size());
				SetWindowTextA(hEditResult, buffer);
			}
			else
			{
				std::string output;
				output = std::to_string(functionsLeft.size()) + " functions left\r\n";
				for (auto &item : functionsLeft)
				{
					dprintf("%p\n", (PVOID)item);
					std::stringstream stream;
					stream << std::hex << (PVOID)item;
					std::string hexStrAddr(stream.str());
					output += hexStrAddr;
					output += "\r\n";
					SetWindowTextA(hEditResult, output.c_str());
				}
			}
			
			return TRUE;
		}
		else if (LOWORD(wParam) == IDC_BUTTON2)
		{
			// scan functions button click

			// find all functions in main modules, reset call count, and set condition break point to start record

			SetWindowTextA(hEditResult, "");

			FindAllUserFunctions();

			Cmd("bc");

			EnableWindow(hButtonSearch, FALSE);
			EnableWindow(hButtonReset, FALSE);
			EnableWindow(hButtonNewSearch, FALSE);
			EnableWindow(hEditCallCount, FALSE);
			EnableWindow(hEditResult, FALSE);
			EnableWindow(hCheckExeOnly, FALSE);
			CloseHandle(CreateThread(0, 0, SettingBreakPointThread, 0, 0, 0));
		}
		else if (LOWORD(wParam) == IDC_BUTTON3)
		{
			// new search click

			// reset hit count
			constexpr int cmdSize = 0x100;
			char cmd[cmdSize];
			int cnt = 0;
			for (auto &item : g_functionCallCount)
			{
				sprintf_s(cmd, cmdSize, "ResetBreakpointHitCount %p", (PVOID)item.first);
				Cmd(cmd);
				item.second = 0;
			}
			dprintf("all %d functions call count reset\n", g_functionCallCount.size());
		}
		else if (LOWORD(wParam) == IDC_CHECK1)
		{
			// "only exe functions" checkbox event

			if (IsDlgButtonChecked(hwndDlg, IDC_CHECK1))
			{
				g_scanExeOnly = true;
			}
			else
			{
				g_scanExeOnly = false;
			}
		}
		break;
	case WM_CLOSE:
		ShowWindow(hwndDlg, SW_HIDE);
		return TRUE;
	}
	return FALSE;
}

//Do GUI/Menu related things here.
void pluginSetup()
{


	_plugin_menuaddentry(g_hMenu, MENU_MAINWINDOW_POPUP, "Call Finder");
	//_plugin_menuaddentry(g_hMenu, MENU_ABOUT_POPUP, "About");
}

//Deinitialize your plugin data here.
void pluginStop()
{

}

// register menu to popup main window
extern "C" __declspec(dllexport) void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info)
{
	if (!g_pluginDlg)
	{
		new std::thread(([&]() {
			DialogBoxA(g_hInstance, MAKEINTRESOURCEA(IDD_DIALOG1), 0, DialogProc);
		}));
		return;
	}
	
	switch (info->hEntry)
	{
	case MENU_MAINWINDOW_POPUP:
		ShowWindow(g_pluginDlg, IsWindowVisible(g_pluginDlg) ? SW_HIDE : SW_SHOW);
		break;
	//case MENU_ABOUT_POPUP:
	//	MessageBoxA(0, "author: ", "About", MB_OK);
	//	break;
	}
	
}



