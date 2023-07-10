#include "plugin.h"

#ifdef _UNICODE
#error "USE ASCII CODE PAGE"
#endif

using namespace Script::Module;
using namespace Script::Symbol;
using namespace Script::Debug;
using namespace Script::Register;


void SystemBreakpointCallback(CBTYPE bType, void*callbackInfo);
void BpCallback(CBTYPE bType, void*callbackInfo);

std::map<duint, bool> g_breakpoints;

bool g_scanExeOnly = true; // only scan exe by default
bool g_fastMode = true;

HWND g_pluginDlg = 0;
HWND hButtonSearch;
HWND hButtonReset;
HWND hButtonNewSearch;
HWND hEditCallCount;
HWND hEditResult;
HWND hCheckExeOnly;
HWND hCheckFastMode;

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
	_plugin_registercallback(g_pluginHandle, CB_SYSTEMBREAKPOINT, SystemBreakpointCallback);
	_plugin_registercallback(g_pluginHandle, CB_BREAKPOINT, BpCallback);

	return true; //Return false to cancel loading the plugin.
}

// disable ui before set breakpoint, otherwise it will cause the UI to block
void DisableUi()
{
	GuiUpdateDisable();
}

void EnableUi()
{
	GuiUpdateEnable(true);
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

bool IsBadInstruction(duint addr)
{
	constexpr int cmdSize = 0x100;
	char cmd[cmdSize];
	sprintf_s(cmd, cmdSize, "dis.next(dis.prev(%p)) != %p", (PVOID)addr, (PVOID)addr);
	return DbgEval(cmd) ? true : false;
}

std::string DisasmAddress(duint addr)
{
	DISASM_INSTR di;
	DbgDisasmAt((duint)addr, &di);
	return di.instruction;
}

bool IsInstructionContains(duint addr, LPCSTR keyword)
{
	if (IsBadInstruction(addr))
		return false;

	std::string ins = DisasmAddress(addr);
	if (ins.find(keyword) != std::string::npos) {
		return true;
	}
	return false;
}

duint NextInstruct(duint addr)
{
	if (IsBadInstruction(addr))
		return addr + 1;

	constexpr int cmdSize = 0x100;
	char cmd[cmdSize];
	sprintf_s(cmd, cmdSize, "dis.next(%p)", (PVOID)addr);
	return DbgEval(cmd);
}

void DeleteBreakpointsExceptOEP()
{
	DisableUi();
	
	ModuleInfo mainModuleInfo;
	Script::Module::GetMainModuleInfo(&mainModuleInfo);
	duint oep = mainModuleInfo.entry;

	BPMAP bplist;
	int bpCnt = DbgGetBpList(bp_normal, &bplist);
	if (bpCnt)
	{
		for (int i = 0; i < bpCnt; i++)
		{
			if (bplist.bp[i].addr != oep)
			{
				Script::Debug::DeleteBreakpoint(bplist.bp[i].addr);
			}
		}
		BridgeFree(bplist.bp);
	}

	EnableUi();
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

	size_t originCnt = g_breakpoints.size();

	duint unCheckedPage = base;

	int totalFound = 0;

	Script::Module::ModuleInfo mInfo;
	Script::Module::InfoFromAddr(base, &mInfo);

	while (addr < endAddress)
	{
		// scanning new page, check if it's code
		if ((unCheckedPage == PAGE_ALIGN(addr)))
		{
			sprintf_s(cmd, cmdSize, "mem.iscode(%p)", (PVOID)unCheckedPage);
			if (DbgEval(cmd))
			{
				// new page is code
				unCheckedPage += PAGE_SIZE;
			}
			else
			{
				// new page is not code
				addr = PAGE_ALIGN(addr) + PAGE_SIZE;
				unCheckedPage += PAGE_SIZE;
			}
		}

		if (IsBadInstruction(addr))
		{
			addr++;
			continue;
		}

		sprintf_s(cmd, cmdSize, "dis.iscall(%p)", (PVOID)addr);
		if (DbgEval(cmd))
		{
			// addr is call, try to eval dst address
			DISASM_INSTR di;
			DbgDisasmAt((duint)addr, &di);
			duint FuncAddr = di.arg[0].value;
			
			// is dst a user function ?
			sprintf_s(cmd, cmdSize, "mem.iscode(%p) && mod.user(%p)", (PVOID)FuncAddr, (PVOID)FuncAddr);
			if (DbgEval(cmd))
			{
				if (!g_fastMode)
				{
					if (g_breakpoints.count(FuncAddr) == 0)
					{
						g_breakpoints[FuncAddr] = true;
						totalFound++;
					}
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
						if (g_breakpoints.count(FuncAddr) == 0)
						{
							g_breakpoints[FuncAddr] = true;
							totalFound++;
						}
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
						// invalid call instruction
					}
					else
					{
						if (!IsBadInstruction(addr))
						{
							if (g_breakpoints.count(addr) == 0)
							{
								g_breakpoints[addr] = true;
								totalFound++;
							}
						}
					}
				}
			}
		}

		if ((totalFound % 100) == 0)
		{
			char msg[0x100] = { 0 };
			sprintf_s(msg, 0x100, "%d functions found in %s", totalFound, mInfo.name);
			SetWindowTextA(hEditResult, msg);
		}

		//addr = NextInstruct(addr);
		addr++;
	}
	return int(g_breakpoints.size() - originCnt);
}

// find all user functions, store in global map
void FindAllUserFunctions()
{
	g_breakpoints.clear();

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
	DeleteBreakpointsExceptOEP();
}

void BpCallback(CBTYPE bType, void*callbackInfo)
{
	PLUG_CB_BREAKPOINT *info = (PLUG_CB_BREAKPOINT*)callbackInfo;
	if (info->breakpoint->hitCount > 64)
	{
		info->breakpoint->active = false;
		DeleteBreakpoint(info->breakpoint->addr);
		g_breakpoints.erase(info->breakpoint->addr);
		if (GuiIsUpdateDisabled())
			GuiUpdateEnable(true);
		UpdateWindow(GuiGetWindowHandle());
		
		char msg[0x100] = { 0 };
		sprintf_s(msg, 0x100, "auto remove breakpoint %p", (PVOID)info->breakpoint->addr);
		SetWindowTextA(hEditResult, msg);
		UpdateWindow(g_hwndDlg);
	}
	
}

unsigned __stdcall SettingBreakPointThread(void*)
{
	FindAllUserFunctions();

	SetWindowTextA(hEditResult, "setting break point...");

	size_t total = g_breakpoints.size();
	size_t current = 0;

	DisableUi();
	for (auto &item : g_breakpoints)
	{
		duint addr = item.first;
		SetBreakPointNotBreak(addr);
		if ((current % 100) == 0)
		{
			char msg[0x100] = { 0 };
			sprintf_s(msg, 0x100, "%Id / %Id", current, total);
			SetWindowTextA(hEditResult, msg);
		}
		current++;
	}
	EnableUi();

	constexpr int outputSize = 0x100;
	char output[outputSize] = { 0 };
	sprintf_s(output, outputSize, "%Id user functions found\r\nsetting break points may block x64dbg window for a while\r\nstart record!\r\nclick new search button to reset call count", g_breakpoints.size());
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

			// remove uninteresting breakpoints

			char buffer[256];
			GetWindowTextA(GetDlgItem(hwndDlg, IDC_EDIT1), buffer, 256);
			int count = 0;
			sscanf_s(buffer, "%d", &count);
			dprintf("searching functions of hit count %d\n", count);

			std::vector<duint> bpToDelete;
			BPMAP bplist;
			int bpCnt = DbgGetBpList(bp_normal, &bplist);
			if (bpCnt)
			{
				for (int i = 0; i < bpCnt; i++)
				{
					if (bplist.bp[i].hitCount != count)
					{
						bpToDelete.push_back(bplist.bp[i].addr);
					}
				}
				BridgeFree(bplist.bp);
			}
			
			DisableUi();
			for (auto &bp : bpToDelete)
			{
				DeleteBreakpoint(bp);
				g_breakpoints.erase(bp);
			}
			EnableUi();

			if (g_breakpoints.size() > 100)
			{
				constexpr int bufferSize = 0x100;
				sprintf_s(buffer, bufferSize, "%Id functions left\r\ntoo many function found, result will not show", g_breakpoints.size());
				SetWindowTextA(hEditResult, buffer);
			}
			else
			{
				std::string output;
				output = std::to_string(g_breakpoints.size()) + " functions left\r\n";
				for (auto &item : g_breakpoints)
				{
					dprintf("%p\n", (PVOID)item.first);
					std::stringstream stream;
					stream << std::hex << (PVOID)item.first;
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

			SetWindowTextA(hEditResult, "scanning...");
			
			EnableWindow(hButtonSearch, FALSE);
			EnableWindow(hButtonReset, FALSE);
			EnableWindow(hButtonNewSearch, FALSE);
			EnableWindow(hEditCallCount, FALSE);
			EnableWindow(hEditResult, FALSE);
			EnableWindow(hCheckExeOnly, FALSE);
			EnableWindow(hCheckFastMode, FALSE);
			UpdateWindow(g_hwndDlg);

			DeleteBreakpointsExceptOEP();
			CloseHandle((HANDLE)_beginthreadex(0, 0, SettingBreakPointThread, 0, 0, 0));
		}
		else if (LOWORD(wParam) == IDC_BUTTON3)
		{
			// new search click

			// reset hit count
			constexpr int cmdSize = 0x100;
			char cmd[cmdSize];
			int cnt = 0;
			for (auto &item : g_breakpoints)
			{
				sprintf_s(cmd, cmdSize, "ResetBreakpointHitCount %p", (PVOID)item.first);
				Cmd(cmd);
			}
			dprintf("all %d functions call count reset\n", g_breakpoints.size());
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



