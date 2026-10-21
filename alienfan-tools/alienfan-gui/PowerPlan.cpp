#include "PowerPlan.h"
#include <powrprof.h>
#include <shlobj.h>
#include <algorithm>
#include <vector>

#pragma comment(lib,"PowrProf.lib")

using namespace std;

const char* PowerPlan::levelNames[] = { "Power saver", "Balanced", "High Performance", "Ultimate Performance", "" };

static const GUID noGuid{};

// Built-in plan templates: a1841308-..., 381b4222-..., 8c5e7fda-..., e9a42b02-...
static const GUID planTemplates[PowerPlan::levels] = {
	{ 0xa1841308, 0x3928, 0x454c, { 0xb6, 0x36, 0x9a, 0xc6, 0xaa, 0xab, 0x4a, 0x04 } },
	{ 0x381b4222, 0xf694, 0x41f0, { 0x96, 0x85, 0xff, 0x5b, 0xb2, 0x60, 0xdf, 0x2e } },
	{ 0x8c5e7fda, 0xe8bf, 0x4a96, { 0x9a, 0x85, 0xa6, 0xe2, 0x3a, 0x8c, 0x63, 0x5c } },
	{ 0xe9a42b02, 0xd5df, 0x448d, { 0xaa, 0x00, 0x03, 0xf1, 0x47, 0x49, 0xeb, 0x61 } }
};
// English names of the built-in plans, used to find copies made earlier outside the app.
static const wchar_t* planNames[PowerPlan::levels] = { L"Power saver", L"Balanced", L"High performance", L"Ultimate Performance" };

// Power mode overlays used on Modern Standby systems: 961cc777-..., Balanced (null), 3af9b8d9-..., ded574b5-...
static const GUID overlays[PowerPlan::levels] = {
	{ 0x961cc777, 0x2547, 0x4f9d, { 0x81, 0x74, 0x7d, 0x86, 0x18, 0x1b, 0x8a, 0x7a } },
	{ 0 },
	{ 0x3af9b8d9, 0x7c97, 0x431d, { 0xad, 0x78, 0x34, 0xa8, 0xbf, 0xea, 0x43, 0x9f } },
	{ 0xded574b5, 0x45a0, 0x4f42, { 0x87, 0x37, 0x46, 0x34, 0x5c, 0x09, 0xc2, 0x38 } }
};
static const char* overlayNames[PowerPlan::levels] = { "Best power efficiency", "Balanced", "Better performance", "Best performance" };

// Overlay functions are exported by powrprof.dll but not declared in the SDK.
typedef DWORD(WINAPI* GetOverlayFn)(GUID* overlay);
typedef DWORD(WINAPI* SetOverlayFn)(GUID overlay);

static FARPROC PowrProf(const char* name) {
	static HMODULE lib = LoadLibraryEx("powrprof.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	return lib ? GetProcAddress(lib, name) : NULL;
}

struct PowerPlanJob {
	HWND notify;
	int level;
	bool modernStandby;
	GUID stored;   // in: plan copy remembered for this level
	GUID resolved; // out: plan activated for this level
	string error;  // out: empty on success
};

static string GuidToString(const GUID& g) {
	char buf[37];
	sprintf_s(buf, "%08lx-%04hx-%04hx-%02x%02x-%02x%02x%02x%02x%02x%02x", g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
	return buf;
}

// Parses "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" at the start of text.
static bool ParseGuid(const char* text, GUID& out) {
	static const char pattern[] = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx";
	for (int i = 0; pattern[i]; i++)
		if (pattern[i] == '-' ? text[i] != '-' : !isxdigit((unsigned char)text[i]))
			return false;
	unsigned long d1;
	unsigned int d2, d3, b[8];
	if (sscanf_s(text, "%8lx-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x", &d1, &d2, &d3,
		&b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7]) != 11)
		return false;
	out = { d1, (unsigned short)d2, (unsigned short)d3 };
	for (int i = 0; i < 8; i++)
		out.Data4[i] = (unsigned char)b[i];
	return true;
}

// First GUID in powercfg output other than skip.
static bool FindGuid(const string& output, const GUID& skip, GUID& out) {
	for (size_t pos = 0; pos + 36 <= output.size(); pos++)
		if (ParseGuid(output.c_str() + pos, out) && out != skip)
			return true;
	return false;
}

static string ErrorText(DWORD code) {
	char* msg = NULL;
	DWORD len = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, code, 0, (LPSTR)&msg, 0, NULL);
	string text = len ? string(msg, len) : "Unknown error";
	LocalFree(msg);
	while (text.size() && isspace((unsigned char)text.back()))
		text.pop_back();
	return text + " (" + to_string(code) + ")";
}

static vector<GUID> EnumSchemes() {
	vector<GUID> schemes;
	GUID scheme;
	DWORD size = sizeof(GUID);
	for (ULONG i = 0; PowerEnumerate(NULL, NULL, NULL, ACCESS_SCHEME, i, (UCHAR*)&scheme, &size) == ERROR_SUCCESS; i++, size = sizeof(GUID))
		schemes.push_back(scheme);
	return schemes;
}

static bool HasScheme(const vector<GUID>& schemes, const GUID& scheme) {
	return find(schemes.begin(), schemes.end(), scheme) != schemes.end();
}

static wstring SchemeName(const GUID& scheme) {
	DWORD size = 0;
	if (PowerReadFriendlyName(NULL, &scheme, NULL, NULL, NULL, &size) != ERROR_SUCCESS || size < sizeof(wchar_t))
		return {};
	wstring name(size / sizeof(wchar_t), 0);
	if (PowerReadFriendlyName(NULL, &scheme, NULL, NULL, (UCHAR*)&name[0], &size) != ERROR_SUCCESS)
		return {};
	name.resize(wcslen(name.c_str()));
	return name;
}

// Plan for a level: the installed built-in plan, the copy remembered in settings, or an existing plan named
// like the built-in one (a copy made earlier outside the app). noGuid if none exists.
// Templates stay readable even when not installed, so only enumeration proves a built-in plan exists;
// for copies a readable name is enough.
static GUID ResolvePlan(int level, const GUID& stored, const vector<GUID>& schemes) {
	if (HasScheme(schemes, planTemplates[level]))
		return planTemplates[level];
	if (stored != noGuid && SchemeName(stored).size())
		return stored;
	wstring localName = SchemeName(planTemplates[level]);
	for (auto& scheme : schemes) {
		wstring name = SchemeName(scheme);
		if (!_wcsicmp(name.c_str(), planNames[level]) || (localName.size() && name == localName))
			return scheme;
	}
	return noGuid;
}

// Runs powercfg with no console window. Returns its exit code, or a Win32 error if it can't start.
static DWORD RunPowercfg(const string& args, string& output) {
	char sysDir[MAX_PATH];
	UINT len = GetSystemDirectory(sysDir, MAX_PATH);
	if (!len || len >= MAX_PATH) {
		output = "Cannot locate the system directory.";
		return ERROR_PATH_NOT_FOUND;
	}
	string cmd = "\"" + string(sysDir, len) + "\\powercfg.exe\" " + args;
	SECURITY_ATTRIBUTES sa{ sizeof(sa), NULL, TRUE };
	HANDLE readPipe, writePipe;
	if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
		DWORD err = GetLastError();
		output = "Cannot start powercfg: " + ErrorText(err);
		return err;
	}
	SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
	STARTUPINFO si{ sizeof(si) };
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = si.hStdError = writePipe;
	PROCESS_INFORMATION pi;
	DWORD code;
	if (CreateProcess(NULL, &cmd[0], NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
		CloseHandle(writePipe);
		char buf[512];
		DWORD read;
		while (ReadFile(readPipe, buf, sizeof(buf), &read, NULL) && read)
			output.append(buf, read);
		WaitForSingleObject(pi.hProcess, INFINITE);
		if (!GetExitCodeProcess(pi.hProcess, &code))
			code = GetLastError();
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		// console tools write the OEM code page
		OemToCharBuffA(output.data(), &output[0], (DWORD)output.size());
		while (output.size() && isspace((unsigned char)output.back()))
			output.pop_back();
	}
	else {
		code = GetLastError();
		CloseHandle(writePipe);
		output = "Cannot start powercfg: " + ErrorText(code);
	}
	CloseHandle(readPipe);
	return code;
}

static string SwitchPlan(PowerPlanJob* job) {
	string name = PowerPlan::levelNames[job->level];
	GUID plan = ResolvePlan(job->level, job->stored, EnumSchemes());
	if (plan == noGuid) {
		string output;
		if (DWORD code = RunPowercfg("-duplicatescheme " + GuidToString(planTemplates[job->level]), output)) {
			if (!IsUserAnAdmin())
				return "Creating the " + name + " plan requires administrator rights.\nRestart Alienware Fan Control as administrator and try again.";
			return "powercfg could not create the " + name + " plan (code " + to_string(code) + "):\n" + output;
		}
		if (!FindGuid(output, planTemplates[job->level], plan) || SchemeName(plan).empty())
			return "powercfg did not report the new " + name + " plan:\n" + output;
	}
	job->resolved = plan;
	if (DWORD err = PowerSetActiveScheme(NULL, &plan))
		return "Windows refused to activate the " + name + " plan: " + ErrorText(err);
	return {};
}

static string SwitchOverlay(int level) {
	auto setOverlay = (SetOverlayFn)PowrProf("PowerSetActiveOverlayScheme");
	if (!setOverlay)
		return "This Windows version does not support power modes.";
	GUID* active = NULL;
	if (DWORD err = PowerGetActiveScheme(NULL, &active))
		return "Cannot read the active power plan: " + ErrorText(err);
	bool balanced = *active == planTemplates[1];
	LocalFree(active);
	// Power modes only apply on top of the Balanced plan.
	if (!balanced)
		if (DWORD err = PowerSetActiveScheme(NULL, &planTemplates[1]))
			return "Windows refused to activate the Balanced plan: " + ErrorText(err);
	if (DWORD err = setOverlay(overlays[level]))
		return string("Windows refused to set the \"") + overlayNames[level] + "\" power mode: " + ErrorText(err);
	return {};
}

static DWORD WINAPI SwitchWorker(LPVOID param) {
	PowerPlanJob* job = (PowerPlanJob*)param;
	job->error = job->modernStandby ? SwitchOverlay(job->level) : SwitchPlan(job);
	if (!PostMessage(job->notify, WM_POWERPLAN_DONE, 0, (LPARAM)job))
		delete job; // window is gone
	return 0;
}

static VOID WINAPI ModeChanged(EFFECTIVE_POWER_MODE mode, VOID* context) {
	PostMessage((HWND)context, WM_POWERPLAN_CHANGED, 0, 0);
}

PowerPlan::PowerPlan(HWND notify) : notifyWnd(notify) {
	// Same capability powercfg /a reports as "Standby (S0 Low Power Idle)", without parsing localized text.
	SYSTEM_POWER_CAPABILITIES caps{};
	modernStandby = !CallNtPowerInformation(SystemPowerCapabilities, NULL, 0, &caps, sizeof(caps)) && caps.AoAc;

	if (RegCreateKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Alienfan\\PowerPlans", 0, NULL, REG_OPTION_NON_VOLATILE,
		KEY_READ | KEY_WRITE, NULL, &keyPlans, NULL) == ERROR_SUCCESS) {
		for (int i = 0; i < levels; i++) {
			char value[64];
			DWORD size = sizeof(value);
			if (RegGetValue(keyPlans, NULL, ("Plan-" + to_string(i)).c_str(), RRF_RT_REG_SZ, NULL, value, &size) == ERROR_SUCCESS)
				ParseGuid(value, created[i]);
		}
	}
	else
		keyPlans = NULL;

	schemeNotify = RegisterPowerSettingNotification(notifyWnd, &GUID_ACTIVE_POWERSCHEME, DEVICE_NOTIFY_WINDOW_HANDLE);
	if (modernStandby && FAILED(PowerRegisterForEffectivePowerModeNotifications(EFFECTIVE_POWER_MODE_V1, ModeChanged, notifyWnd, &modeNotify)))
		modeNotify = NULL;
}

PowerPlan::~PowerPlan() {
	if (modeNotify)
		PowerUnregisterFromEffectivePowerModeNotifications(modeNotify);
	if (schemeNotify)
		UnregisterPowerSettingNotification(schemeNotify);
	// A running worker owns its job and drops it if the window is gone.
	if (worker)
		CloseHandle(worker);
	if (keyPlans)
		RegCloseKey(keyPlans);
}

int PowerPlan::GetActiveLevel() {
	GUID* activePtr = NULL;
	if (PowerGetActiveScheme(NULL, &activePtr) != ERROR_SUCCESS)
		return -1;
	GUID active = *activePtr;
	LocalFree(activePtr);
	if (modernStandby) {
		auto getOverlay = (GetOverlayFn)PowrProf("PowerGetEffectiveOverlayScheme");
		GUID overlay;
		if (active != planTemplates[1] || !getOverlay || getOverlay(&overlay) != ERROR_SUCCESS)
			return -1;
		for (int i = 0; i < levels; i++)
			if (overlay == overlays[i])
				return i;
		return -1;
	}
	vector<GUID> schemes = EnumSchemes();
	for (int i = 0; i < levels; i++)
		if (active == ResolvePlan(i, created[i], schemes))
			return i;
	return -1;
}

bool PowerPlan::SetLevel(int level) {
	if (worker || level < 0 || level >= levels)
		return false;
	PowerPlanJob* job = new PowerPlanJob{ notifyWnd, level, modernStandby, created[level] };
	if (!(worker = CreateThread(NULL, 0, SwitchWorker, job, 0, NULL))) {
		delete job;
		return false;
	}
	return true;
}

string PowerPlan::Finish(LPARAM param) {
	PowerPlanJob* job = (PowerPlanJob*)param;
	int level = job->level;
	if (job->resolved != noGuid && job->resolved != planTemplates[level] && job->resolved != created[level]) {
		created[level] = job->resolved;
		string value = GuidToString(created[level]);
		if (keyPlans)
			RegSetValueEx(keyPlans, ("Plan-" + to_string(level)).c_str(), 0, REG_SZ, (const BYTE*)value.c_str(), (DWORD)value.size() + 1);
	}
	string error = job->error;
	delete job;
	CloseHandle(worker);
	worker = NULL;
	return error;
}
