#pragma once
#include <windows.h>
#include <string>

// Posted to the notify window when a background switch ends; pass lParam to PowerPlan::Finish().
#define WM_POWERPLAN_DONE (WM_APP + 3)
// Posted to the notify window when Windows reports a power mode (overlay) change.
#define WM_POWERPLAN_CHANGED (WM_APP + 4)

// Switches Windows between four performance levels.
// Classic systems: power plans (missing plans are created with powercfg -duplicatescheme).
// Modern Standby (S0 Low Power Idle) systems: power mode overlays on top of Balanced; plans are never created.
class PowerPlan {
private:
	HWND notifyWnd;
	HKEY keyPlans = NULL;
	GUID created[4]{}; // plan copies made for levels whose built-in plan is missing, persisted in settings
	HPOWERNOTIFY schemeNotify = NULL;
	PVOID modeNotify = NULL;
	HANDLE worker = NULL;
public:
	static const int levels = 4;
	static const char* levelNames[levels + 1];
	bool modernStandby = false;

	// Detects the mode and registers for change notifications. Active plan changes arrive at the
	// notify window as WM_POWERBROADCAST/PBT_POWERSETTINGCHANGE with GUID_ACTIVE_POWERSCHEME.
	PowerPlan(HWND notify);
	~PowerPlan();

	bool Busy() { return worker != NULL; }
	// Active level, or -1 when the active plan or mode is none of the four levels.
	int GetActiveLevel();
	// Starts a background switch; false if one is already running or the thread can't start.
	bool SetLevel(int level);
	// Completes a switch on WM_POWERPLAN_DONE. Returns the error text, empty on success.
	std::string Finish(LPARAM job);
};
