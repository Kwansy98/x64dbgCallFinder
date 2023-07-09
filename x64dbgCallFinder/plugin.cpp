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
void AttachCallback(CBTYPE bType, void*callbackInfo);
void BreakPointCallback(CBTYPE bType, void*callbackInfo);

std::map<duint, int> g_functionCallCount;

duint g_oep = 0;
bool g_scanExeOnly = true; // only scan exe by default
bool g_fastMode = true;

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
	Cmd("cleardb");
	_plugin_registercallback(g_pluginHandle, CB_SYSTEMBREAKPOINT, SystemBreakpointCallback);
	_plugin_registercallback(g_pluginHandle, CB_DETACH, DetachCallback);
	_plugin_registercallback(g_pluginHandle, CB_DETACH, AttachCallback);
	_plugin_registercallback(g_pluginHandle, CB_BREAKPOINT, BreakPointCallback);

	return true; //Return false to cancel loading the plugin.
}

void DisableLogAndUi()
{
	Cmd("LogDisable");
	GuiUpdateDisable();
	GuiDisableLog();
}

void EnableLogAndUi()
{
	Cmd("LogEnable");
	GuiUpdateEnable(true);
	GuiEnableLog();
}

void SetBreakPointNotBreak(duint addr)
{
	constexpr int cmdSize = 0x100;
	char cmd[cmdSize];

	sprintf_s(cmd, cmdSize, "bp %p", (PVOID)addr);
	Cmd(cmd);
	sprintf_s(cmd, cmdSize, "bpcnd %p,\"0\"", (PVOID)addr); // break if 0
	Cmd(cmd);
}

bool IsInstructionContains(duint addr, LPCSTR keyword)
{
	constexpr int cmdSize = 0x100;
	char cmd[cmdSize];
	sprintf_s(cmd, cmdSize, "strstr(dis.text(%p), \"%s\")", (PVOID)addr, keyword);
	return DbgEval(cmd) ? true : false;
}

bool IsInstructionUnusual(duint addr)
{
	constexpr int cmdSize = 0x100;
	char cmd[cmdSize];
	sprintf_s(cmd, cmdSize, "dis.isunusual(%p)", (PVOID)addr);
	return DbgEval(cmd) ? true : false;
}

// find all user defined functions in secific module, return number of functions found
int ScanFunctionOnModule(duint base, duint size)
{
	constexpr int cmdSize = 0x100;
	char cmd[cmdSize] = { 0 };
	duint startAddress = base;
	duint endAddress = base + size;
	duint addr = startAddress;
	addr = PAGE_ALIGN(addr);

	size_t originCnt = g_functionCallCount.size();

	while (addr < endAddress)
	{
		// if not code, then skip this page
		if (((ULONG_PTR)addr == PAGE_ALIGN(addr)))
		{
			sprintf_s(cmd, cmdSize, "mem.iscode(%p)", (PVOID)addr);
			if (!DbgEval(cmd))
			{
				addr = addr + PAGE_SIZE;
				continue;
			}
		}

		// is call ?
		sprintf_s(cmd, cmdSize, "dis.iscall(%p)", (PVOID)addr);
		if (DbgEval(cmd))
		{
			// try to eval dst address
			DISASM_INSTR di;
			DbgDisasmAt((duint)addr, &di);
			duint FuncAddr = di.arg[0].value;
			
			// is dst a user function ?
			sprintf_s(cmd, cmdSize, "mem.iscode(%p) && mod.user(%p)", (PVOID)FuncAddr, (PVOID)FuncAddr);
			if (DbgEval(cmd))
			{
				if (!g_fastMode)
				{
					g_functionCallCount[FuncAddr] = 0;
				}
				else
				{
					// fast mode does more checks because we want to minimize the number of breakpoints
					if (IsInstructionContains(FuncAddr, "mov ") ||
						IsInstructionContains(FuncAddr, "push ") ||
						IsInstructionContains(FuncAddr, "sub ") ||
						IsInstructionContains(FuncAddr, "lea ") ||
						IsInstructionContains(FuncAddr, "cmp ") ||
						IsInstructionContains(FuncAddr, "xor "))
					{
						g_functionCallCount[FuncAddr] = 0;
					}
				}
			}
			else
			{
				// can't get dst addr, or dst not a user function, only thing we can do is set breakpoint at call instruction
				sprintf_s(cmd, cmdSize, "dis.iscallsystem(%p)", (PVOID)addr);
				if (!DbgEval(cmd))
				{
					sprintf_s(cmd, cmdSize, "dis.imm(%p) != 0 && !mem.iscode(dis.imm(%p))", (PVOID)addr, (PVOID)addr);
					if (DbgEval(cmd))
					{
						// invalid instruction
					}
					else
					{
						sprintf_s(cmd, cmdSize, "dis.next(dis.prev(%p)) == %p", (PVOID)addr, (PVOID)addr);
						if (DbgEval(cmd))
						{
							g_functionCallCount[addr] = 0;
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

	EnableLogAndUi();
}

void BreakPointCallback(CBTYPE bType, void*callbackInfo)
{
}

void DetachCallback(CBTYPE bType, void*callbackInfo)
{
	Cmd("bc");

	EnableLogAndUi();
}

void AttachCallback(CBTYPE bType, void*callbackInfo)
{
	Cmd("bc");

	EnableLogAndUi();
}

HWND g_pluginDlg = 0;
HWND hButtonSearch;
HWND hButtonReset;
HWND hButtonNewSearch;
HWND hEditCallCount;
HWND hEditResult;
HWND hCheckExeOnly;
HWND hCheckFastMode;

DWORD WINAPI SettingBreakPointThread(LPVOID)
{
	FindAllUserFunctions();

	SetWindowTextA(hEditResult, "setting break point...");

	DisableLogAndUi();
	for (auto &item : g_functionCallCount)
	{
		duint addr = item.first;
		SetBreakPointNotBreak(addr);
	}
	EnableLogAndUi();

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
	EnableWindow(hCheckFastMode, TRUE);
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
		hCheckFastMode = GetDlgItem(hwndDlg, IDC_CHECK2);
		Button_SetCheck(hCheckExeOnly, BST_CHECKED); // only scan exe by default
		Button_SetCheck(hCheckFastMode, BST_CHECKED); // fast mode default

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
						// this function we don't interest in
						DeleteBreakpoint(bplist.bp[i].addr);
						g_functionCallCount.erase(bplist.bp[i].addr);
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

			Cmd("bc");

			EnableWindow(hButtonSearch, FALSE);
			EnableWindow(hButtonReset, FALSE);
			EnableWindow(hButtonNewSearch, FALSE);
			EnableWindow(hEditCallCount, FALSE);
			EnableWindow(hEditResult, FALSE);
			EnableWindow(hCheckExeOnly, FALSE);
			EnableWindow(hCheckFastMode, FALSE);
			UpdateWindow(g_hwndDlg);
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
		else if (LOWORD(wParam) == IDC_CHECK2)
		{
			if (IsDlgButtonChecked(hwndDlg, IDC_CHECK2))
			{
				g_fastMode = true;
			}
			else
			{
				g_fastMode = false;
			}
		}
		return TRUE;
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

	// create a infinity thread, disable uninsterest breakpoints
	new std::thread(([&]() {
		while (1)
		{
			BPMAP bplist;
			int bpCnt = DbgGetBpList(bp_normal, &bplist);
			if (bpCnt)
			{
				for (int i = 0; i < bpCnt; i++)
				{
					if (bplist.bp[i].hitCount > 100)
					{
						DeleteBreakpoint(bplist.bp[i].addr);
						g_functionCallCount.erase(bplist.bp[i].addr);
					}
				}
				BridgeFree(bplist.bp);
			}
			Sleep(3000);
		}
	}));
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
	}
}



