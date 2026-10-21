#include "Common.h"
#include <windowsx.h>
#include <WinInet.h>
#include <algorithm>
//#include <Psapi.h>

using namespace std;

#pragma comment(lib,"Wininet.lib")
#pragma comment(lib,"Version.lib")

extern HWND mDlg;
extern HMODULE hInst;
extern bool needUpdateFeedback, isNewVersion;
extern int idc_version, idc_homepage;

INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
	case WM_INITDIALOG: {
		SetDlgItemText(hDlg, idc_version, ("Version: " + GetAppVersion()).c_str());
	} break;
	case WM_COMMAND:
		switch (LOWORD(wParam)) {
		case IDOK: case IDCANCEL:
		{
			EndDialog(hDlg, LOWORD(wParam));
		} break;
		}
		break;
	case WM_NOTIFY:
		if (LOWORD(wParam) == idc_homepage) {
			switch (((LPNMHDR)lParam)->code)
			{
			case NM_CLICK:
			case NM_RETURN:
			{
				ShellExecute(NULL, "open", "https://github.com/gfnord/alienfx-tools", NULL, NULL, SW_SHOWNORMAL);
			} break;
			} break;
		}
		break;
	default: return (INT_PTR)FALSE;
	}
	return (INT_PTR)TRUE;
}

DWORD WINAPI Blinker(LPVOID lparam) {
	int howmany = (((int)lparam) + 1) << 1;
	for (int i = 0; i < howmany; i++) {
		keybd_event(VK_CAPITAL, 0x3A, 0, 0);
		keybd_event(VK_CAPITAL, 0x3A, KEYEVENTF_KEYUP, 0);
		Sleep(300);
	}
	return 0;
}

void BlinkNumLock(int howmany) {
	CreateThread(NULL, 0, Blinker, (LPVOID)(ULONGLONG)howmany, 0, NULL);
}

bool WarningBox(HWND hDlg, const char* msg) {
	return GetKeyState(VK_SHIFT) & 0xf0 || MessageBox(hDlg, msg, "Warning", MB_YESNO | MB_ICONWARNING) == IDYES;
}

bool EvaluteToAdmin(HWND dlg) {
	// Evaluation attempt...
	if (!IsUserAnAdmin()) {
		char szPath[MAX_PATH];
		GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath));
		// Launch itself as admin
		SHELLEXECUTEINFO sei{ sizeof(sei), 0, NULL, "runas", szPath, NULL, NULL, SW_NORMAL };
		if (ShellExecuteEx(&sei)) {
			// Quit this instance
			if (dlg)
				SendMessage(dlg, WM_CLOSE, 0, 0);
			else
				_exit(1);
		}
		return false;
	}
	return true;
}

bool TryStopService(SC_HANDLE handle, bool kind, const char* name) {
	bool rCode = false;
	SC_HANDLE schService = OpenService(handle, name, SERVICE_START | SERVICE_STOP);
	if (schService) {
		SERVICE_STATUS  serviceStatus;
		rCode = kind ? ControlService(schService, SERVICE_CONTROL_STOP, &serviceStatus) :
			StartService(schService, 0, NULL);
		CloseServiceHandle(schService);
	}
	return rCode;
}

bool DoStopAWCC(bool flag, bool kind) {
	bool rCode = false;
	if (flag && EvaluteToAdmin()) {
		SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, GENERIC_READ);
		if (schSCManager) {
			if (!(rCode = TryStopService(schSCManager, kind, "AWCCService"))) {
				if (TryStopService(schSCManager, kind, "DellClientManagementService")) {
					rCode = TryStopService(schSCManager, kind, "DellTechHub");
				}
			}
			CloseServiceHandle(schSCManager);
		}
	}
	return rCode;
}

void ResetDPIScale(LPWSTR cmdLine) {
	HKEY dpiKey;
	if (RegCreateKeyEx(HKEY_CURRENT_USER, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers"),
		0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &dpiKey, NULL) == ERROR_SUCCESS) {
		char pathBuffer[2048];
		GetModuleFileNameA(NULL, pathBuffer, 2047);
		const char setValue[] = "~ GDIDPISCALING DPIUNAWARE";
		RegSetValueEx(dpiKey, pathBuffer, 0, REG_SZ, (byte*)setValue, (DWORD)strlen(setValue));
		RegCloseKey(dpiKey);
	}
	if (wcslen(cmdLine)) {
		Sleep(_wtoi(cmdLine) * 1000);
	}
}

void ShowNotification(NOTIFYICONDATA* niData, string title, string message) {
	strcpy_s(niData->szInfoTitle, title.c_str());
	strcpy_s(niData->szInfo, message.c_str());
	niData->uFlags |= NIF_INFO;
	//niData->dwInfoFlags = NIIF_ERROR;
	if (!Shell_NotifyIcon(NIM_MODIFY, niData))
		Shell_NotifyIcon(NIM_ADD, niData);
	niData->uFlags &= ~NIF_INFO;
}

// True if version a (dotted, up to 4 numeric parts, optional leading 'v') is newer than b.
static bool IsNewerVersion(string a, const string& b) {
	unsigned va[4]{}, vb[4]{};
	if (a.size() && (a[0] == 'v' || a[0] == 'V'))
		a.erase(0, 1);
	sscanf_s(a.c_str(), "%u.%u.%u.%u", &va[0], &va[1], &va[2], &va[3]);
	sscanf_s(b.c_str(), "%u.%u.%u.%u", &vb[0], &vb[1], &vb[2], &vb[3]);
	return lexicographical_compare(vb, vb + 4, va, va + 4);
}

DWORD WINAPI CUpdateCheck(LPVOID lparam) {
	NOTIFYICONDATA* niData = (NOTIFYICONDATA*)lparam;
	HINTERNET session, req = NULL;
	DWORD byteRead;
	if (!needUpdateFeedback)
		// check connection for some seconds
		for (int delay = 0; delay < 15 && !InternetGetConnectedState(&byteRead, 0); delay++)
			Sleep(1000);
	if (InternetGetConnectedState(&byteRead, 0) && (session = InternetOpen("alienfan-gui", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0))) {
		// Latest published release; no "tag_name" until the first release exists.
		if (req = InternetOpenUrl(session, "https://api.github.com/repos/gfnord/alienfx-tools/releases/latest",
			NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, NULL)) {
			string res;
			char buf[1024];
			while (InternetReadFile(req, buf, sizeof(buf), &byteRead) && byteRead)
				res.append(buf, byteRead);
			size_t pos = res.find("\"tag_name\""), start, end;
			if (pos != string::npos && (pos = res.find(':', pos)) != string::npos &&
				(start = res.find('"', pos)) != string::npos && (end = res.find('"', ++start)) != string::npos) {
				string tag = res.substr(start, end - start);
				if (IsNewerVersion(tag, GetAppVersion(false))) {
					// new version detected!
					ShowNotification(niData, "Update available!", "Latest version is " + tag);
					isNewVersion = true;
				} else
					if (needUpdateFeedback)
						ShowNotification(niData, "You are up to date!", "You are using latest version.");
			}
			InternetCloseHandle(req);
		}
		InternetCloseHandle(session);
	}
	if (needUpdateFeedback && !req)
			ShowNotification(niData, "Update check failed!", "Can't connect to GitHub for update check.");
	needUpdateFeedback = false;
	return 0;
}

bool WindowsStartSet(bool kind) {
	char szProcessName[MAX_PATH]{ 0 };
	GetModuleFileName(NULL, szProcessName, MAX_PATH);
	//processdata procName = GetProcessData(GetCurrentProcessId());// ParseFileName(szProcessName);
	string procName = string(szProcessName);
	string appPath = procName.substr(0, procName.find_last_of('\\') + 1);
	string taskName = procName.substr(appPath.length(), procName.find_last_of('.') - appPath.length());
	if (kind) {
		return ShellExecute(NULL, "runas", "powershell.exe", ("Register-ScheduledTask -TaskName \"" + taskName +
			"\" -trigger $(New-ScheduledTaskTrigger -Atlogon) -settings $(New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0) -action $(New-ScheduledTaskAction -Execute '"
			+ procName + "' -WorkingDirectory '" + appPath +
			"') -force -RunLevel Highest").c_str(), NULL, SW_HIDE) > (HINSTANCE)32;
	}
	else {
		return ShellExecute(NULL, "runas", "schtasks.exe", ("/delete /F /TN \"" + taskName + "\"").c_str(), NULL, SW_HIDE) > (HINSTANCE)32;
	}
}

string GetAppVersion(bool isFile) {
	string res;

	//HMODULE hInst = GetModuleHandle(NULL);
	HGLOBAL hResData = LoadResource(hInst, FindResource(hInst, MAKEINTRESOURCE(VS_VERSION_INFO), RT_VERSION));

	if (hResData) {
		LPVOID pRes = LockResource(hResData);
		UINT uLen = 0;
		DWORD MS, LS;
		VS_FIXEDFILEINFO* lpFfi = NULL;

		VerQueryValue(pRes/*Copy*/, TEXT("\\"), (LPVOID*)&lpFfi, &uLen);

		if (isFile) {
			MS = lpFfi->dwFileVersionMS;
			LS = lpFfi->dwFileVersionLS;
		}
		else {
			MS = lpFfi->dwProductVersionMS;
			LS = lpFfi->dwProductVersionLS;
		}

		res = to_string(HIWORD(MS)) + "."
			+ to_string(LOWORD(MS)) + "."
			+ to_string(HIWORD(LS)) + "."
			+ to_string(LOWORD(LS));

		FreeResource(hResData);
	}

	return res;
}

void CreateToolTip(HWND hwndParent, HWND& oldTip)
{
	// Create a tool tip.
	if (oldTip) DestroyWindow(oldTip);

	oldTip = CreateWindowEx(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL,
		WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
		0, 0, 0, 0, hwndParent, NULL, hInst, NULL);
	TOOLINFO ti{ sizeof(TOOLINFO), TTF_SUBCLASS | TTF_TRANSPARENT, hwndParent };
	GetClientRect(hwndParent, &ti.rect);
	SendMessage(oldTip, TTM_ADDTOOL, 0, (LPARAM)&ti);
}

void CreateToolTip(HWND hwndParent, HWND& oldTip, int value)
{
	// Create a tool tip and init it
	CreateToolTip(hwndParent, oldTip);
	SetSlider(oldTip, value);
}

HWND SetToolTip(HWND tt, string value) {
	if (tt) {
		TOOLINFO ti{ sizeof(TOOLINFO) };
		SendMessage(tt, TTM_ENUMTOOLS, 0, (LPARAM)&ti);
		ti.lpszText = (LPTSTR)value.c_str();
		SendMessage(tt, TTM_SETTOOLINFO, 0, (LPARAM)&ti);
		return ti.hwnd;
	}
	return NULL;
}

void SetSlider(HWND tt, int value) {
	HWND parent = SetToolTip(tt, to_string(value));
	if (parent) {
		SendMessage(parent, TBM_SETPOS, true, value);
	}
}

void UpdateCombo(HWND ctrl, const char* items[], int sel, const int val[]) {
	ComboBox_ResetContent(ctrl);
	for (int i = 0; items[i][0]; i++) {
		ComboBox_AddString(ctrl, items[i]);
		if (val) {
			ComboBox_SetItemData(ctrl, i, val[i]);
			if (sel == val[i])
				ComboBox_SetCurSel(ctrl, i);
		}
		else
			if (sel == i)
				ComboBox_SetCurSel(ctrl, sel);
	}
}

void UpdateCombo(HWND ctrl, const string* items, int sel, vector<int> val) {
	ComboBox_ResetContent(ctrl);
	for (int i = 0; items[i].size(); i++) {
		ComboBox_AddString(ctrl, items[i].c_str());
		if (val.size()) {
			ComboBox_SetItemData(ctrl, i, val[i]);
			if (sel == val[i])
				ComboBox_SetCurSel(ctrl, i);
		}
		else
			if (sel == i)
				ComboBox_SetCurSel(ctrl, sel);
	}
}

bool AddTrayIcon(NOTIFYICONDATA* iconData, bool needCheck) {
	if (!Shell_NotifyIcon(NIM_MODIFY, iconData) && !Shell_NotifyIcon(NIM_ADD, iconData))
			return false;
	if (needCheck)
		CreateThread(NULL, 0, CUpdateCheck, iconData, 0, NULL);
	return true;
}
