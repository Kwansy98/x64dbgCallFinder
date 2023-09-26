#include "plugin.h"

#ifdef _UNICODE
#error "USE ASCII CODE PAGE"
#endif

using namespace Script::Module;
using namespace Script::Symbol;
using namespace Script::Debug;
using namespace Script::Register;

// Delaying execution when setting breakpoints can reduce the probability of UI blocking
#define DELAY_MAGIC() Sleep(50)

class BreakPointManager
{
private:
	std::map<duint, bool> breakpoints;

public:

	~BreakPointManager()
	{
		Clear();
	}

	void Clear()
	{
		for (auto &item : breakpoints)
		{
			RemoveBreakPoint(item.first);
		}
	}

	void SetBreakPoint(duint addr)
	{
		if (breakpoints.find(addr) != breakpoints.end())
		{
			return;
		}

		constexpr int cmdSize = 0x100;
		char cmd[cmdSize];

		sprintf_s(cmd, cmdSize, "bp %p", (PVOID)addr);
		Cmd(cmd);
		sprintf_s(cmd, cmdSize, "bpcnd %p,\"0\"", (PVOID)addr); // break if 0
		Cmd(cmd);

		breakpoints[addr] = true;

		DELAY_MAGIC();
	}

	void RemoveBreakPoint(duint addr)
	{
		Script::Debug::DeleteBreakpoint(addr);

		breakpoints.erase(addr);
	}

	std::vector<duint> FilterBreakPointsWithCallCount(duint count)
	{
		std::vector<duint> bps;

		BPMAP bplist;
		int bpCnt = DbgGetBpList(bp_normal, &bplist);
		if (bpCnt)
		{
			for (int i = 0; i < bpCnt; i++)
			{
				// only handle our breakpoints
				if (breakpoints.find(bplist.bp[i].addr) != breakpoints.end())
				{
					if (bplist.bp[i].hitCount == count)
					{
						bps.push_back(bplist.bp[i].addr);
					}
					else
					{
						RemoveBreakPoint(bplist.bp[i].addr);
					}
				}
			}
			BridgeFree(bplist.bp);
		}

		return bps;
	}

	size_t GetBreakPointsCount()
	{
		return breakpoints.size();
	}
};

BreakPointManager g_BreakpointsManager;

HWND g_pluginDlg = 0;
HWND hButtonSearch;
HWND hButtonReset;
HWND hButtonNewSearch;
HWND hEditCallCount;
HWND hEditResult;
HWND hEditAddrStart;
HWND hEditAddrEnd;

void SystemBreakpointCallback(CBTYPE bType, void*callbackInfo);

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
	_plugin_registercallback(g_pluginHandle, CB_SYSTEMBREAKPOINT, SystemBreakpointCallback);
	return true; //Return false to cancel loading the plugin.
}

void SystemBreakpointCallback(CBTYPE bType, void*callbackInfo)
{
	g_BreakpointsManager.Clear();
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

// find all user defined functions in secific address range, and then set breakpoints
size_t ScanFunctionsAndSetBreakPoints(duint base, duint size)
{
	g_BreakpointsManager.Clear();

	constexpr int cmdSize = 0x100;
	char cmd[cmdSize] = { 0 };
	duint startAddress = base;
	duint endAddress = base + size;
	duint addr = startAddress;
	addr = PAGE_ALIGN(addr);

	duint unCheckedPage = base;

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
				if (IsInstructionContains(FuncAddr, "mov ") ||
					IsInstructionContains(FuncAddr, "push ") ||
					IsInstructionContains(FuncAddr, "sub ") ||
					IsInstructionContains(FuncAddr, "lea ") ||
					IsInstructionContains(FuncAddr, "cmp ") ||
					IsInstructionContains(FuncAddr, "xor "))
				{
					g_BreakpointsManager.SetBreakPoint(FuncAddr);
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
							g_BreakpointsManager.SetBreakPoint(addr);
						}
					}
				}
			}
		}

		//addr = NextInstruct(addr);
		addr++;
	}

	return g_BreakpointsManager.GetBreakPointsCount();
}

INT_PTR CALLBACK PickDllDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	static std::vector<ModuleInfo> *dlls = nullptr;

	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		dlls = new std::vector<ModuleInfo>;
		HWND hwndList = GetDlgItem(hwndDlg, IDC_LIST_DLL);

		// receive all dlls
		ListInfo listInfo;
		if (Script::Module::GetList(&listInfo))
		{
			for (int i = 0; i < listInfo.count; i++)
			{
				ModuleInfo *mInfo = &((ModuleInfo *)listInfo.data)[i];
				dlls->push_back(*mInfo);
			}
			BridgeFree(listInfo.data);
		}

		std::sort(dlls->begin(), dlls->end(), [](const ModuleInfo &m1, const ModuleInfo &m2) {
			
			return m1.base < m2.base;
		});

		for (size_t i = 0; i < dlls->size(); i++)
		{
			// add to list box
			int pos = (int)SendMessageA(hwndList, LB_INSERTSTRING, i,
				(LPARAM)dlls->at(i).name);
		}
		SetFocus(hwndList);
		break;
	}
	case WM_CLOSE: 
	{
		delete dlls;
		EndDialog(hwndDlg, 0);
		return TRUE;
	}
	case WM_COMMAND:
		if (LOWORD(wParam) == IDC_BUTTON_PICK_DLL)
		{
			HWND hwndList = GetDlgItem(hwndDlg, IDC_LIST_DLL);

			// Get selected index.
			int i = (int)SendMessage(hwndList, LB_GETCURSEL, 0, 0);
			if (i >= 0 && (size_t)i < dlls->size())
			{
				char buf[0x100];
				sprintf_s(buf, _countof(buf), "%p", (PVOID)dlls->at(i).base);
				SetWindowTextA(hEditAddrStart, buf);
				sprintf_s(buf, _countof(buf), "%p", (PVOID)(dlls->at(i).base + dlls->at(i).size));
				SetWindowTextA(hEditAddrEnd, buf);

				SendMessageA(hwndDlg, WM_CLOSE, 0, 0);
			}
		}
		return TRUE;
	}
	return FALSE;
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
		hEditAddrStart = GetDlgItem(hwndDlg, IDC_EDIT_ADDR_START);
		hEditAddrEnd = GetDlgItem(hwndDlg, IDC_EDIT_ADDR_END);

		return TRUE;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDC_BUTTON1)
		{
			/*
			Search button click

			Get the number of calls input by the user from the edit box, 
			and then delete the breakpoints that do not meet the conditions
			*/

			char buffer[256];
			GetWindowTextA(GetDlgItem(hwndDlg, IDC_EDIT1), buffer, 256);
			int count = 0;
			sscanf_s(buffer, "%d", &count);
			dprintf("searching functions of hit count %d\n", count);

			std::vector<duint> breakpointsLeft = g_BreakpointsManager.FilterBreakPointsWithCallCount(count);

			std::string output;
			output = std::to_string(breakpointsLeft.size()) + " functions left\r\n";
			for (auto &item : breakpointsLeft)
			{
				dprintf("%p\n", (PVOID)item);
				std::stringstream stream;
				stream << std::hex << (PVOID)item;
				std::string hexStrAddr(stream.str());
				output += hexStrAddr;
				output += "\r\n";
				SetWindowTextA(hEditResult, output.c_str());
			}
			
			return TRUE;
		}
		else if (LOWORD(wParam) == IDC_BUTTON2)
		{
			/*
			scan functions button click

			Get the user-specified address range from the edit box, 
			scan the functions within the address range, and set conditional breakpoints
			*/

			SetWindowTextA(hEditResult, "scanning...");
			
			EnableWindow(hButtonSearch, FALSE);
			EnableWindow(hButtonReset, FALSE);
			EnableWindow(hButtonNewSearch, FALSE);
			EnableWindow(hEditCallCount, FALSE);
			EnableWindow(hEditResult, FALSE);
			UpdateWindow(g_hwndDlg);

			PVOID addrStart = NULL;
			PVOID addrEnd = NULL;
			char buffer[256];
			GetWindowTextA(GetDlgItem(hwndDlg, IDC_EDIT_ADDR_START), buffer, 256);
			sscanf_s(buffer, "%p", &addrStart);
			GetWindowTextA(GetDlgItem(hwndDlg, IDC_EDIT_ADDR_END), buffer, 256);
			sscanf_s(buffer, "%p", &addrEnd);
			dprintf("scanning address range: %p -> %p\n", addrStart, addrEnd);

			size_t cnt = ScanFunctionsAndSetBreakPoints((duint)addrStart, (duint)addrEnd - (duint)addrStart);
			sprintf_s(buffer, _countof(buffer), "%Id breakpoints set", cnt);
			SetWindowTextA(hEditResult, buffer);

			EnableWindow(hButtonSearch, TRUE);
			EnableWindow(hButtonReset, TRUE);
			EnableWindow(hButtonNewSearch, TRUE);
			EnableWindow(hEditCallCount, TRUE);
			EnableWindow(hEditResult, TRUE);
			UpdateWindow(g_hwndDlg);
		}
		else if (LOWORD(wParam) == IDC_BUTTON_PICK)
		{
			DialogBoxA(g_hInstance, MAKEINTRESOURCEA(IDD_DIALOG2), hwndDlg, PickDllDialogProc);
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



