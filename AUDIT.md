# Security & Code-Quality Audit — gfnord/alienfx-tools

**Subject:** `gfnord/alienfx-tools` (fork of `T-Troll/alienfx-tools`)
**Audit date:** 2026-06-24
**Audit type:** Static, read-only. No source files modified.
**Scope:** Fork divergence vs upstream + full review of backdoors / exfiltration / persistence / privilege-escalation / obfuscation / memory safety.

---

## 0. Top-line Verdict

| Item | Result | Confidence |
| --- | --- | --- |
| **Fork tampering** | **None.** Fork is byte-for-byte identical to upstream `master @ 5df7065`. | **Definitive** (`git diff` empty, reflog clean) |
| **Malicious code** | **None found.** No backdoor, no telemetry, no covert persistence, no obfuscation, no dynamic-loaded payload. | **High** |
| **Network exfiltration** | **None.** Sole egress is a documented `GET https://api.github.com/repos/t-troll/alienfx-tools/tags?per_page=1` update check. Independently verified — only 2 Internet-API hits in entire codebase, both in the documented function. | **High** |
| **DXGI screen-capture egress** | **None.** Captured frames stay in local heap; only output is per-cell RGB averages sent to USB HID via `WriteFile` for ambient lighting. | **High** |
| **Persistence beyond docs** | **None.** Registry writes confined to `HKCU\Software\Alienf*`. One user-opt-in scheduled task. One documented `HwAcc` user-mode service for ACPI access. | **High** |
| **Privilege escalation** | **As documented.** Three `ShellExecuteEx("runas", ...)` sites, all gated on user-selected admin features. | **High** |
| **Obfuscation / dynamic loading** | **None.** Zero anti-debug, zero anti-VM, zero shellcode, zero reflective DLL load, zero base64/XOR string obfuscation. XOR ops present are HID protocol checksums. | **High** |
| **Memory & resource bugs** | **6 verified, mostly Low/Medium.** No Critical, no exploitable corruption. See §4 + §6. | **High** |

**Bottom line: The codebase is a legitimate Alienware/Dell-G hardware utility. The fork adds nothing.** The behaviors that trip antivirus heuristics (HID byte tables resembling shellcode, ACPI ioctl, DXGI capture, low-level keyboard hooks, PowerShell-launched scheduled task, unsigned `HwAcc.sys` driver via `kdl.dll`) are all documented and necessary for the stated hardware-control functionality. See [§5 — Legitimate-but-AV-flagged behaviors](#5--legitimate-but-av-flagged-behaviors).

---

## 1. Fork Divergence

Upstream remote added (`https://github.com/T-Troll/alienfx-tools.git`) and full fetch performed:

| Check | Result |
| --- | --- |
| `git merge-base master upstream/master` | `5df7065f6f9afdfbd1a470ea3bb45a60a6df4fa9` |
| Upstream `master` HEAD | `5df7065 Gauges and fixes` |
| Fork `master` HEAD | `5df7065 Gauges and fixes` |
| `git log upstream/master..master` (fork-only commits) | **empty** (0 commits) |
| `git log master..upstream/master` (commits we're missing) | **empty** (0 commits) |
| `git diff upstream/master..master` | **empty** (0 changed files) |
| `git status --porcelain --untracked-files=all` | **empty** (clean working tree, no untracked) |
| `git stash list` | empty |
| `git reflog` | single entry (initial `clone` on 2026-06-24, no rewrites) |
| `.git/hooks/` non-sample files | none |
| Fork-only tags | none |
| Local branches | only `master`, points at the same upstream commit |
| Custom remotes (besides origin/upstream) | none |

**Conclusion:** the on-disk tree IS upstream `master @ 5df7065`. The remainder of this audit therefore evaluates the *upstream* code, since the fork contributes nothing to attack surface.

### 1.1 Binary blob inventory

`git ls-files` scanned for every potentially-executable / opaque blob extension (`.exe .dll .sys .bin .dat .cab .msi .so .o .lib .obj .pdb .res`):

| Category | Count | Files |
| --- | --- | --- |
| Pre-compiled executables/libraries/drivers | **0** | — |
| Application icons (`.ico`) | 6 | [alienfan-gui.ico](alienfan-tools/alienfan-gui/alienfan-gui.ico), [alien.ico](alienfx-gui/alien.ico), [alien_dim.ico](alienfx-gui/alien_dim.ico), [alien_off.ico](alienfx-gui/alien_off.ico), [alien_on.ico](alienfx-gui/alien_on.ico), [alienfx-mon.ico](alienfx-mon/alienfx-mon.ico) |
| Documentation images (`.png`) | 18 | All under [Doc/img/](Doc/img/) |
| Intel DPTF policy descriptors (`.dvx`) | 2 | [startup.dvx](DPTF/startup.dvx) (248B), [remoteui.dvx](DPTF/remoteui.dvx) (256B) — Intel DPTF data files, **not** drivers; copied by the USER to `Windows\System32\drivers\DriverData\Intel\DPTF\dv\` per [README:51](README.md#L51). Hex dump shows only plaintext strings `startup`, `Startup Configuration`, `Remote UI Startup Configuration`, `KEYS`, `start` plus a small XOR-obfuscated body (standard DPTF DV format). |

**No pre-compiled binary payloads ship in the source tree.**

### 1.2 Build-step / install-script inventory

| Check | Result |
| --- | --- |
| `PreBuildEvent` / `PostBuildEvent` / `CustomBuildStep` / `<Exec>` / `<Command>` across all 15 `.vcxproj`/`.props`/`.targets` | **0 hits** |
| [`Install/Install.vdproj`](Install/Install.vdproj) `CustomAction` block (line 303) | empty `{ }` |
| [`Install/Install.vdproj`](Install/Install.vdproj) `Registry` blocks (lines 818–848 — HKLM/HKCU/HKCR/HKU/HKPU) | all empty `Keys { }` |
| [`Install/Install.vdproj`](Install/Install.vdproj) `PreBuildEvent` / `PostBuildEvent` / `RunPostBuildEvent` (lines 812–814) | empty / `3:0` |
| [`Install/Install.vdproj`](Install/Install.vdproj) Shortcuts (lines 852–895) | 3 Start Menu shortcuts to AlienFan Control, AlienFX Monitor, AlienFX Control — benign |
| [`alienfx-config.cmd`](alienfx-config.cmd) | pure `reg export`/`reg import`/`reg delete` on `HKCU\Software\Alienf*` only |
| `.bat` / `.ps1` / `.sh` scripts | none |

**No build-time or install-time code execution.** The MSI installer only deposits files and creates Start Menu shortcuts.

---

## 2. Findings — Backdoors / Exfiltration

### 2.1 Network surface (FULL ENUMERATION)

Independent grep across the entire tree for `InternetOpenUrl|InternetReadFile|WinHttpOpen|HttpOpenRequest|HttpSendRequest|URLDownloadToFile|WSAStartup|socket\s*\(|connect\s*\(`:

| File:Line | Code | Classification | Severity |
| --- | --- | --- | --- |
| [Common/Common.cpp:148](Common/Common.cpp:148) | `InternetGetConnectedState(&byteRead, 0) && (session = InternetOpen("alienfx-tools", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0))` | Documented update check, uses system proxy config | Informational |
| [Common/Common.cpp:149](Common/Common.cpp:149) | `InternetOpenUrl(session, "https://api.github.com/repos/t-troll/alienfx-tools/tags?per_page=1", NULL, 0, INTERNET_FLAG_RELOAD \| INTERNET_FLAG_NO_CACHE_WRITE, NULL)` | GET-only, no headers, no auth, no body | Informational |
| [Common/Common.cpp:151](Common/Common.cpp:151) | `InternetReadFile(req, buf, 254, &byteRead)` | Reads max 254 bytes | Informational |

**That is the complete network surface.** 0 hits for: `WinHttp*`, `HttpOpenRequest`, `URLDownloadToFile`, raw sockets, `WSAStartup`, `connect()`, `bind()`, `listen()`, `gethostbyname`, `getaddrinfo`, `DnsQuery`, `CreateNamedPipe`, `RpcServerListen`, MAPI/CDO, Bluetooth, mailslot, IXmlHTTP.

### 2.2 Update-check end-to-end trace

[`CUpdateCheck` at Common/Common.cpp:139–183](Common/Common.cpp:139):

1. Wait up to 15 seconds for any internet connection.
2. `InternetOpen("alienfx-tools", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0)` — user-agent literally `"alienfx-tools"` (no machine ID, no hostname). Respects user's system-proxy config.
3. GET `https://api.github.com/repos/t-troll/alienfx-tools/tags?per_page=1` with `INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE`. No custom headers, no cookies, no body.
4. Read up to 254 bytes into a stack buffer.
5. Parse: substring after `"name":` up through next `"` → version string.
6. Normalize version to `X.Y.Z.W`, compare with local resource via [`GetAppVersion(false)` at Common/Common.cpp:203](Common/Common.cpp:203).
7. If newer, raise local tray notification. Otherwise silent.
8. `InternetCloseHandle(req); InternetCloseHandle(session);`.

**No data is sent outbound beyond the URL query string.** No hardware ID, no MAC, no machine name, no installed-software inventory, no crash reports, no telemetry.

All 4 callers of `CUpdateCheck` invoke this same function (verified independently): [`Common.cpp:313`](Common/Common.cpp:313), [`alienfan-gui.cpp:306`](alienfan-tools/alienfan-gui/alienfan-gui.cpp:306), [`alienfan-gui.cpp:535`](alienfan-tools/alienfan-gui/alienfan-gui.cpp:535), [`alienfx-gui.cpp:434`](alienfx-gui/alienfx-gui.cpp:434), [`alienfx-mon.cpp:590`](alienfx-mon/alienfx-mon.cpp:590).

### 2.3 DXGI screen-capture data flow (ambient mode)

Traced from acquisition to consumption:

| Stage | Location | What happens |
| --- | --- | --- |
| Frame acquisition | [DXGIManager.cpp:91](alienfx-gui/DXGIManager.cpp:91) | `m_dxgi_output_dup->AcquireNextFrame(...)` — Desktop Duplication API |
| Map to CPU | [DXGIManager.cpp:296](alienfx-gui/DXGIManager.cpp:296) | `frame_surface->Map(&mapped_surface, DXGI_MAP_READ)` |
| Copy to local heap | [DXGIManager.cpp:331–340](alienfx-gui/DXGIManager.cpp:331) | `memcpy(m_frame_buf, mapped_surface.pBits, ...)` — `m_frame_buf` is a private `DXGIManager` member |
| Color averaging | [CaptureHelper.cpp:158–195](alienfx-gui/CaptureHelper.cpp:158) | Each grid cell reduced to either average RGB or "prevailing color" — pure CPU math |
| Storage | [CaptureHelper.cpp:133–134](alienfx-gui/CaptureHelper.cpp:133) + [`imgz` declared at CaptureHelper.h:23](alienfx-gui/CaptureHelper.h:23) | Local heap arrays (`imgz`, `imgo`) — never escape the process |
| Consumption | [CaptureHelper.cpp:234](alienfx-gui/CaptureHelper.cpp:234) | `fxhl->RefreshAmbient()` → ultimately `WriteFile(devHandle, buffer, ...)` to the USB HID lighting device |

**No network API, no file write outside the program's own config, no shared memory, no named pipe, no clipboard, no socket touches the captured pixel buffer.**

### 2.4 Other potential egress vectors — all benign or absent

| Category | Hits | Verdict |
| --- | --- | --- |
| Clipboard (`OpenClipboard`, `GetClipboardData`) | 0 | absent |
| Email APIs (`MAPI`, `CDO`) | 0 | absent |
| Bluetooth (`BluetoothFindFirstDevice`) | 0 | absent |
| Named pipes (`CreateNamedPipe`) | 0 | absent |
| RPC server (`RpcServerListen`, `RpcServerUseProtseq`) | 0 | absent |
| Telemetry / analytics SDKs (`sentry`, `crashpad`, `breakpad`, `appcenter`, `firebase`, `posthog`, `mixpanel`, `datadog`, ...) | 0 | absent |
| Hardcoded credentials / API keys / JWTs | 0 | absent |
| Low-level keyboard hooks (`WH_KEYBOARD_LL`) | 3 sites — [EventHandler.cpp:273](alienfx-gui/EventHandler.cpp:273), [EventHandler.cpp:282](alienfx-gui/EventHandler.cpp:282), [GridHelper.cpp:161](alienfx-gui/GridHelper.cpp:161), plus [KeyPressDialog.cpp:41](alienfx-gui/KeyPressDialog.cpp:41) | **Profile-switching hotkey, action-timeout detector, grid-effect trigger, key-capture UI dialog.** Hooks only inspect key codes for matching, NEVER buffer/forward keystrokes. Not a keylogger. |
| Process enumeration (`EnumProcesses`, `OpenProcess`) | [EventHandler.cpp:48](alienfx-gui/EventHandler.cpp:48), [EventHandler.cpp:236](alienfx-gui/EventHandler.cpp:236) | Profile auto-switching based on foreground app — documented. |
| URL `ShellExecute` (documentation links) | 5 sites, all `github.com/T-Troll/alienfx-tools/...` | user-initiated "Open homepage" / "Open releases" buttons |
| Hardcoded IPs / non-GitHub domains | 0 | absent (all `https://` hits are `github.com` or `microsoft.com` docs link in README) |

---

## 3. Findings — Persistence / Privilege Escalation / Build & Install

### 3.1 Registry write scope — full inventory

Every persistent registry write across the codebase, grouped by hive/key:

| Hive\\Key | Files writing | Classification |
| --- | --- | --- |
| `HKCU\SOFTWARE\Alienfx_SDK` | [AlienFX_SDK.cpp:1027,1089](AlienFX-SDK/AlienFX_SDK/AlienFX_SDK.cpp:1027) | **Documented config storage** |
| `HKCU\SOFTWARE\Alienfan` | [ConfigFan.cpp:8–10](alienfan-tools/alienfan-shared/ConfigFan.cpp:8) | **Documented config storage** |
| `HKCU\SOFTWARE\Alienfxgui` | [ConfigHandler.cpp:21–23](alienfx-gui/ConfigHandler.cpp:21) | **Documented config storage** |
| `HKCU\SOFTWARE\Alienfxmain`, `HKCU\SOFTWARE\Alienfxmon\Sensors` | [ConfigMon.cpp:14,33,82–94](alienfx-mon/ConfigMon.cpp:14) | **Documented config storage** |
| `HKCU\Software\Microsoft\Windows\DWM` | [ConfigHandler.cpp:25](alienfx-gui/ConfigHandler.cpp:25) | **Read-only** access to accent color — benign |
| `HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` | [Common.cpp:116–121](Common/Common.cpp:116) | DPI scaling fix for own executable only — benign |

**Zero writes to:** `HKLM\System\CurrentControlSet\Services`, `HKLM\...\Run`, `HKLM\...\RunOnce`, `Image File Execution Options`, `AppInit_DLLs`, `Winlogon`, `Explorer\Shell`, `Policies\Microsoft\Windows Defender`, `Policies\Microsoft\WindowsFirewall`, `SCHEDULE\TaskCache`, `Classes\*\shell\*\command`.

**The MSI installer ([`Install.vdproj`](Install/Install.vdproj))** writes nothing to the registry — verified by inspection of the empty `Keys { }` blocks under `HKLM`, `HKCU`, `HKCR`, `HKU`, `HKPU` (lines 818–848). The user-mode `HKCU\Software\Alienf*` keys are populated at first run by each tool, NOT by the installer.

### 3.2 Service / scheduled-task / autostart

| File:Line | Operation | Classification | Severity |
| --- | --- | --- | --- |
| [alienfan-low.c:148–161](alienfan-tools/alienfan-SDK/alienfan-low/alienfan-low.c:148) | `CreateService(..., SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, ServiceExe, ...)` — creates `HwAcc` user-mode service | **Documented.** Provides the `\\?\GLOBALROOT\Device\HWACC0` ACPI device interface used by fan/power control. Type is `SERVICE_WIN32_OWN_PROCESS`, **not** `SERVICE_KERNEL_DRIVER`. | Medium |
| [alienfan-low.c:230](alienfan-tools/alienfan-SDK/alienfan-low/alienfan-low.c:230) | `DeleteService(schService)` — removes the same `HwAcc` service | **Documented** cleanup path | Low |
| [Common.cpp:92,103](Common/Common.cpp:92) | `StartService` / `ControlService(SERVICE_CONTROL_STOP)` on **AWCC** service | **Documented "Disable AWCC" feature**; user opt-in via Settings dialog | Medium |
| [Common.cpp:193–196](Common/Common.cpp:193) | `ShellExecute(NULL, "runas", "powershell.exe", "Register-ScheduledTask ... -RunLevel Highest")` — register logon auto-start task for own exe | **Documented "Start with Windows" user opt-in.** Task only runs the same exe. | Medium |
| [Common.cpp:199](Common/Common.cpp:199) | `ShellExecute(NULL, "runas", "schtasks.exe", "/delete /F /TN ...")` — remove the above task | **Documented cleanup** | Low |

**Zero hits for:** `ITaskService::RegisterTask` (other than via `schtasks.exe`), WMI `__EventFilter` / `__EventConsumer` / `ActiveScriptEventConsumer` / `CommandLineEventConsumer`, Startup folder drops, `IPersistFile` shortcut drops to `FOLDERID_Startup`.

### 3.3 Privilege escalation — all paths

| File:Line | Code | Trigger |
| --- | --- | --- |
| [Common.cpp:69](Common/Common.cpp:69) | `IsUserAnAdmin()` | Gate before attempting elevation |
| [Common.cpp:73](Common/Common.cpp:73) | `ShellExecuteEx(... lpVerb="runas" ...)` — relaunch self elevated | User selected an admin-required feature |
| [Common.cpp:193](Common/Common.cpp:193) | `ShellExecute(... "runas" ... powershell.exe ...)` | User opted into "Start with Windows" |
| [Common.cpp:199](Common/Common.cpp:199) | `ShellExecute(... "runas" ... schtasks.exe ...)` | User opted out of "Start with Windows" |

**Zero hits for:** `AdjustTokenPrivileges(SE_DEBUG)`, `SE_LOAD_DRIVER`, `SE_TCB`, `SE_CREATE_TOKEN`, `SE_ASSIGNPRIMARYTOKEN`, `SE_IMPERSONATE`, `CreateProcessAsUser`, `CreateProcessWithToken`, `LogonUser`, `ImpersonateLoggedOnUser`, `RtlAdjustPrivilege`.

### 3.4 DLL injection / hooking / inter-process tampering

**Zero hits for:** `CreateRemoteThread`, `NtCreateThreadEx`, `RtlCreateUserThread`, `WriteProcessMemory`, `VirtualAllocEx`, `VirtualProtectEx`, `NtMapViewOfSection`, `QueueUserAPC`, `NtQueueApcThread`, `SetThreadContext`, `GetThreadContext`.

**`SetWinEventHook` / `SetWindowsHookEx` are present**, but only for legitimate UI uses ([EventHandler.cpp:262,267,273,282,283](alienfx-gui/EventHandler.cpp:262), [GridHelper.cpp:161](alienfx-gui/GridHelper.cpp:161), [KeyPressDialog.cpp:41](alienfx-gui/KeyPressDialog.cpp:41)) — foreground-window watch for profile switching, hotkey detection, action-timeout reset. None of these hooks inject code into other processes; `WINEVENT_OUTOFCONTEXT` is used so the hook callback runs in the originating process.

### 3.5 DLL load surface

Only two `LoadLibrary` sites in the entire codebase:

| File:Line | DLL | Purpose | Classification |
| --- | --- | --- | --- |
| [LFXUtil.cpp:45](alienfx-LFX/LFXUtil.cpp:45) | `LFX_DLL_NAME` (resolves to `LightFX.dll`) | Load Dell's LightFX.dll OR the project's own emulator of it, by documented name | **Documented optional feature** |
| [alienfan-SDK.cpp:62](alienfan-tools/alienfan-SDK/alienfan-SDK.cpp:62) | `"kdl.dll"` | External kernel-driver loader used to install the unsigned `HwAcc.sys` for ACPI access | **Documented**, externally maintained |

All subsequent `GetProcAddress` calls use **plaintext literal function names** ([LFXUtil.cpp:49–67](alienfx-LFX/LFXUtil.cpp:49), [alienfan-SDK.cpp:67](alienfan-tools/alienfan-SDK/alienfan-SDK.cpp:67)). No runtime name construction, no resolution of known malware-target functions (`NtCreateThreadEx`, `RtlCreateUserThread`, `NtAllocateVirtualMemory`, etc. — **zero hits**).

### 3.6 Driver / kernel surface

| File:Line | Surface |
| --- | --- |
| [alienfan-SDK.cpp:62–67](alienfan-tools/alienfan-SDK/alienfan-SDK.cpp:62) | `kdl.dll` exports `LoadKernelDriver` — the actual `HwAcc.sys` (a third-party ACPI driver) is loaded by this external library, not by source code in this tree. |
| [alienfan-low.c:606](alienfan-tools/alienfan-SDK/alienfan-low/alienfan-low.c:606) | `CreateFile(_T("\\\\?\\GLOBALROOT\\Device\\HWACC0"), ...)` — opens the already-loaded driver's device interface. |
| [alienfan-low.c:148](alienfan-tools/alienfan-SDK/alienfan-low/alienfan-low.c:148) | `CreateService(... SERVICE_WIN32_OWN_PROCESS ...)` — **user-mode** service registration for `HwAcc` (not a kernel-driver service). |

**Zero hits in this repository for:** `NtLoadDriver`, `ZwLoadDriver`, `SERVICE_KERNEL_DRIVER`, `SERVICE_FILE_SYSTEM_DRIVER`, `inf2cat`, or any source code that writes a `.sys` file to `System32\drivers`.

### 3.7 Embedded resources — full inventory

`FindResource` / `LockResource` callers grep:

| File:Line | RESOURCE_TYPE | Classification |
| --- | --- | --- |
| [Common.cpp:207](Common/Common.cpp:207) | `RT_VERSION` | Version info |
| [LightsDialog.cpp:109,130](alienfx-gui/LightsDialog.cpp:109) | `RT_DIALOG` | Dialog templates |
| [TabDevGrid.cpp:450](alienfx-gui/TabDevGrid.cpp:450) | `RT_DIALOG` | Dialog template |
| [alienfx-gui.cpp:375](alienfx-gui/alienfx-gui.cpp:375) | `RT_DIALOG` | Dialog template |

**Zero `RT_RCDATA` / `RT_BIN` / embedded executable payloads.**

### 3.8 AWCC / security-tool tampering

| Check | Result |
| --- | --- |
| Stop / start of AWCC service | **Documented**, only via the user-opt-in "Disable AWCC" Settings checkbox ([Common.cpp:88–96](Common/Common.cpp:88)) |
| Defender modification (`Set-MpPreference`, `MpCmdRun`, `MSFT_MpPreference`, `Add-MpPreference -ExclusionPath`) | **0 hits** |
| Firewall modification (`netsh advfirewall`, `INetFwPolicy2`) | **0 hits** |
| BCD / boot-file modification | **0 hits** |
| AWCC file deletion / binary modification | **0 hits** |
| Tampering with other services beyond AWCC | **0 hits** |

### 3.9 Empty `alienfx-gui.appmanifest`

[`alienfx-gui/alienfx-gui.appmanifest`](alienfx-gui/alienfx-gui.appmanifest) is 0 bytes. **This is intentional and benign.** Verified by inspecting [`alienfx-gui.vcxproj`](alienfx-gui/alienfx-gui.vcxproj): every `<Manifest />` element across all build configurations (lines 274, 277, 310, 313, 349, 352) is empty, `<AdditionalManifestFiles></AdditionalManifestFiles>` is empty (lines 279–280, 315–316, 354–355). The GUI ships with **no embedded UAC level**, so it runs as `asInvoker` by default and elevates programmatically via the `ShellExecuteEx("runas", ...)` paths above when (and only when) the user enables an admin-required feature. This matches the documented behavior at [README:38](README.md#L38).

---

## 4. Findings — Obfuscation / Dynamic Loading / Anti-Analysis

| Category | Hits | Notes |
| --- | --- | --- |
| Base64/hex-encoded blobs (CryptStringToBinary, custom decode) | **0** | none |
| Stack strings ("S","y","s","t","e","m") | **0** | none |
| Anti-debug (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `NtSetInformationThread`, `PEB.BeingDebugged`, inline `0xCC`, RDTSC timing, `NtClose(invalid)`) | **0** | none |
| Anti-VM (CPUID hypervisor bit, VMware/VBox/QEMU/KVM/Hyper-V/Xen/Parallels string checks, VM-vendor MAC OUIs, BIOS-vendor checks for VM) | **0** | none |
| Shellcode buffers (function-pointer casts of opaque buffers, `PAGE_EXECUTE_READWRITE`, `VirtualProtect → PAGE_EXECUTE`) | **0** | none |
| Reflective / manual DLL loading (`IMAGE_DOS_HEADER`, `IMAGE_NT_HEADERS`, `MemoryModule`, `ReflectiveLoader`, manual import walking) | **0** | none |
| Self-decryption / unpacking (`RtlDecompressBuffer` on self image, `VirtualProtect` on own `.text`) | **0** | none |
| Eval-like (IActiveScript, MSScriptControl, JScript engine, PowerShell `-EncodedCommand`, `FromBase64String`) | **0** | The single PowerShell invocation ([Common.cpp:193](Common/Common.cpp:193)) uses a plaintext `Register-ScheduledTask` cmdlet line, not base64. |
| Dynamic API resolution targeting malware functions (runtime-built name decryption, resolution of `NtCreateThreadEx`/`NtAllocateVirtualMemory`/`RtlAdjustPrivilege`/`NtQueueApcThread`/`WinExec`/`LdrLoadDll`) | **0** | All `GetProcAddress` calls use plaintext string literals for documented APIs. |
| XOR loops over byte arrays | **3 sites** — [AlienFX_SDK.cpp:47](AlienFX-SDK/AlienFX_SDK/AlienFX_SDK.cpp:47), [AlienFX_SDK.cpp:51](AlienFX-SDK/AlienFX_SDK/AlienFX_SDK.cpp:51), [AlienFX_SDK.cpp:57](AlienFX-SDK/AlienFX_SDK/AlienFX_SDK.cpp:57) | All three are inline single-line XOR in `mask ^= ...` checksum updates for the V6 HID lighting protocol. NOT a decryption loop. |

**Conclusion: zero obfuscation, zero anti-analysis, zero dynamic payload loading.** The codebase is fully transparent.

### 4.1 "Looks suspicious but is hardware" — explicit allowlist

These are the patterns that genuinely look like malware but are unambiguously hardware/driver code (each verified by reading the surrounding context):

| Pattern | Files | What it actually is |
| --- | --- | --- |
| Large `const byte[]` arrays sent verbatim to `WriteFile(devHandle, ...)` | [alienfx-controls.h:18–173](AlienFX-SDK/AlienFX_SDK/alienfx-controls.h:18) | USB HID feature-report templates for each of the 8 light-protocol versions documented in [AlienFX-SDK/README.md](AlienFX-SDK/README.md) |
| `const byte functionID[2][19]` | [alienfan-controls.h:17](alienfan-tools/alienfan-SDK_v2/alienfan-controls.h:17) | ACPI method names / opcodes passed to `NtAcpiEvaluateMethod` for fan & power control |
| USB VID/PID switch tables (`0x0d62 Darfon`, `0x187c Alienware`, `0x0424 Microchip`, `0x0461 Primax`, `0x04f2 Chicony`) | [AlienFX_SDK.cpp:197–236](AlienFX-SDK/AlienFX_SDK/AlienFX_SDK.cpp:197) | Vendor-ID dispatch for the various OEMs that make Alienware-compatible RGB devices |
| Large numeric float tables | [`alienfx-gui/kiss_fft/`](alienfx-gui/kiss_fft/) | Bundled Kiss FFT trig lookup tables for the audio spectrum analyzer (haptic/ambient sound mode) |
| `\\\\?\\GLOBALROOT\\Device\\HWACC0` UNC-looking string | [alienfan-low.c:606](alienfan-tools/alienfan-SDK/alienfan-low/alienfan-low.c:606) | NT-kernel object namespace path for the `HwAcc` ACPI driver — NOT a network share |
| `__uuidof(IDXGIFactory1)` / `__uuidof(ID3D11Texture2D)` GUID-looking byte arrays | [DXGIManager.cpp](alienfx-gui/DXGIManager.cpp) | Direct3D11 / DXGI COM-interface GUIDs |

---

## 5. Findings — Memory & Resource Safety

Auditor's note: an upstream automated agent surfaced ~48 candidate findings; after spot-verifying each Critical/High claim against the actual source, the majority were either inaccurate or non-bugs (see [§7 Appendix B](#7-appendix-b--rejected-agent-findings)). The list below contains only findings independently confirmed by reading the source.

| # | File:Line | Bug | Severity | One-line fix |
| --- | --- | --- | --- | --- |
| M1 | [HapticsDialog.cpp:86–87](alienfx-gui/HapticsDialog.cpp:86) | Redundant `DeleteDC(hdc_r)` on a window-DC handle that was already correctly released by `ReleaseDC(hysto, hdc_r)` the line above. On Windows, `DeleteDC` is for `CreateCompatibleDC` results; calling it on a `GetDC` handle is documented as having no effect, but is sloppy and the linter will flag it. | Low | Delete the line `DeleteDC(hdc_r);` — `ReleaseDC` already did the work. |
| M2 | [WSAudioIn.cpp:121–129](alienfx-gui/WSAudioIn.cpp:121) | `IMMDeviceEnumerator* pEnumerator;` declared **uninitialized** at line 123, then checked with `if (pEnumerator)` at line 127 after `CoCreateInstance(..., (void**)&pEnumerator)` at line 126. If `CoCreateInstance` returns a failure HRESULT, the out-param is not guaranteed to be `NULL` — the `if` then reads indeterminate stack memory. | Medium | Change line 123 to `IMMDeviceEnumerator* pEnumerator = NULL;` (or check the `HRESULT` returned by `CoCreateInstance` instead of testing the pointer). |
| M3 | [LightFX.cpp:161,206](LightFX/LightFX.cpp:161) | When `LFX_Initialize` returns `LFX_ERROR_NODEVS` at line 206, the `afx_dev = new AlienFX_SDK::Mappings()` allocated at line 161 is never freed. `LFX_Release` at line 209 only acts when `updateThread` is set (line 210), so subsequent `LFX_Release` returns `LFX_ERROR_NOINIT` without cleaning up `afx_dev`. Repeated load-then-fail by a game would leak the Mappings object each cycle. | Medium | Before `return LFX_ERROR_NODEVS;` at line 206, add `delete afx_dev; afx_dev = NULL;`. |
| M4 | [LightFX.cpp:174–176](LightFX/LightFX.cpp:174) | `stopQuery` and `haveNewElement` events are created unconditionally; if `CreateThread` at line 176 returns `NULL`, both events leak (LFX_Release at line 210 won't run because `updateThread` stays unset). | Low | Check the return of `CreateThread`; on failure, `CloseHandle(stopQuery); CloseHandle(haveNewElement); stopQuery = haveNewElement = NULL;`. |
| M5 | [WSAudioIn.cpp:210–213](alienfx-gui/WSAudioIn.cpp:210) | Four sequential allocations (`kiss_fftr_alloc`, three `new[]`) without rollback. If any of the later `new[]` calls throws `std::bad_alloc`, the earlier allocations leak. In practice Windows process exit reclaims them, but it is not exception-safe. | Low | Wrap each allocation in `std::unique_ptr` (and a small `kiss_fft_cfg` RAII wrapper), or guard with try/catch that frees in reverse order. |
| M6 | [Common.cpp:142,180](Common/Common.cpp:142) | `char* buf = new char[255]` at line 142, `delete[] buf` at line 180; intervening `string` construction at line 153 and `string` concatenations at lines 157–158, 167, 171 can theoretically throw `bad_alloc` and leak `buf`. Same pattern as M5 — current code does not trigger it, but is not exception-safe. | Informational | Use `std::vector<char> buf(255);` or `std::unique_ptr<char[]>`. |

**No Critical findings. No exploitable buffer overflows, double-frees, use-after-frees, or uninitialized control-flow data found.** The codebase's hot paths (HID I/O, DXGI capture, FFT thread) handle their resources correctly via paired allocation/cleanup at the same scope.

### 5.1 Module-level safety summary

| Module | Verified bugs |
| --- | --- |
| `alienfx-gui/HapticsDialog.cpp` | 1 (M1, Low) |
| `alienfx-gui/WSAudioIn.cpp` | 2 (M2 Medium, M5 Low) |
| `LightFX/LightFX.cpp` | 2 (M3 Medium, M4 Low) |
| `Common/Common.cpp` | 1 (M6 Informational) |
| `alienfx-gui/alienfx-gui.cpp`, `DXGIManager.cpp`, `CaptureHelper.cpp`, `EventHandler.cpp`, `GridHelper.cpp`, `FXHelper.cpp`, `ConfigHandler.cpp`, `SysMonHelper.cpp` | No bugs that I independently verified |
| `alienfan-tools/alienfan-SDK/alienfan-SDK.cpp`, `alienfan-low.c` | No bugs that I independently verified |
| `AlienFX-SDK/AlienFX_SDK/AlienFX_SDK.cpp` | No bugs that I independently verified |
| `alienfx-mon/`, `alienfx-cli/`, `alienfx-LFX/`, `RegHelperLib/` | No bugs that I independently verified |

A more exhaustive scrub of error-path resource handling across `SysMonHelper.cpp` (WMI/COM), `alienfan-low.c` (`malloc`/`realloc` in `EvalAcpiMethod`), and `alienfan-SDK.cpp` (ACPI sensor enumeration) is worth doing — those modules have plausible-but-unverified leak candidates from the automated pass that I did not have time to confirm one way or the other. None of them appeared exploitable; they would be slow leaks at most.

---

## 6. Legitimate-but-AV-flagged behaviors

These are the documented, intentional behaviors that DO trigger common antivirus heuristics. The upstream README explicitly notes this happens (versions 4.2.1–6.4.3.2 mentioned at [README:33–35](README.md#L33)). For each, the actual purpose is benign hardware control:

| Behavior | Where | Why AV flags it | Why it's actually fine |
| --- | --- | --- | --- |
| **Loads an unsigned third-party kernel driver (`HwAcc.sys`) via `kdl.dll`** | [alienfan-SDK.cpp:62–67](alienfan-tools/alienfan-SDK/alienfan-SDK.cpp:62) | Unsigned-driver loading is a top-tier malware persistence indicator | The driver provides ACPI BIOS method evaluation (the only way to talk to Alienware fan/power on systems without EC); user opt-in, gated on `requireAdministrator` |
| **Registers a service via SCM (`HwAcc`)** | [alienfan-low.c:148](alienfan-tools/alienfan-SDK/alienfan-low/alienfan-low.c:148) | Service creation = persistence indicator | `SERVICE_DEMAND_START` user-mode service, not `AUTO_START`, doesn't survive reboot unless user keeps the app running |
| **Direct USB/HID `WriteFile` with raw byte buffers that look like shellcode** | [AlienFX_SDK.cpp:124,129,141](AlienFX-SDK/AlienFX_SDK/AlienFX_SDK.cpp:124), [alienfx-controls.h:18–173](AlienFX-SDK/AlienFX_SDK/alienfx-controls.h:18) | Heuristic engines flag opaque byte buffers + raw `WriteFile` to `\\?\HID#...` | These ARE the documented USB HID feature-report layouts for each Alienware/Dell-G lighting protocol version (v0–v8, see [AlienFX-SDK/README.md](AlienFX-SDK/README.md)) |
| **DXGI Desktop Duplication API screen capture** | [DXGIManager.cpp:178,91](alienfx-gui/DXGIManager.cpp:178) | Some AVs flag any non-Snipping-Tool screen-capture as info-stealer behavior | Used for "Ambient" lighting mode — captures local screen, averages to RGB per grid cell, sends to USB HID. Verified frames never leave the process (see §2.3) |
| **Low-level keyboard hook (`WH_KEYBOARD_LL`)** | [EventHandler.cpp:273,282](alienfx-gui/EventHandler.cpp:273), [GridHelper.cpp:161](alienfx-gui/GridHelper.cpp:161), [KeyPressDialog.cpp:41](alienfx-gui/KeyPressDialog.cpp:41) | Keylogger indicator | Used for global hotkeys (profile-switch), action-timeout detection, and a "press a key" UI dialog. Hooks only compare key codes — no buffering, no logging, no exfiltration |
| **Process enumeration via `EnumProcesses` + `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `GetModuleFileNameEx`** | [EventHandler.cpp:48,236](alienfx-gui/EventHandler.cpp:48) | Reconnaissance pattern | Used to match running apps against user-defined profiles (e.g. "when Counter-Strike is running, use this lighting profile") |
| **Self-elevation via `ShellExecuteEx("runas", ...)` and PowerShell-launched `Register-ScheduledTask` with `-RunLevel Highest`** | [Common.cpp:73,193](Common/Common.cpp:73) | UAC bypass / persistence indicator | Always shows the standard UAC consent prompt to the user; the scheduled task only runs the same exe and only when the user enables "Start with Windows" |
| **Reads ESIF / DPTF telemetry (Intel DPTF policy descriptors in [DPTF/](DPTF/))** | runtime via documented Intel framework | Anti-debug / anti-VM heuristics overlap | Intel DPTF (Dynamic Platform & Thermal Framework) is the legitimate Microsoft-sanctioned API for power/thermal data on Intel systems |
| **GitHub update check** | [Common.cpp:148–149](Common/Common.cpp:148) | Any HTTP request from a hardware util raises a flag | GET-only to public GitHub API, no telemetry, respects user proxy. Can be disabled — the call is gated on the user-controlled `needUpdateFeedback` flag and the per-app trigger |

None of these constitute genuine malicious behavior; the README's caveat at lines 33–35 is accurate.

---

## 7. Appendices

### 7.1 Appendix A — Methodology

1. **Fork divergence baseline** (definitive): added upstream remote, fetched all branches/tags, ran `git merge-base`, `git log upstream/master..master`, `git log master..upstream/master`, `git diff upstream/master..master`, `git status --porcelain --untracked-files=all`, `git stash list`, `git reflog`, `.git/hooks/` inspection. Result: 0 divergence.
2. **Mechanical inventory** (non-overlapping): file-type histogram, binary-blob extension grep, build-step grep across all `.vcxproj`/`.props`/`.targets`, full read of [`Install.vdproj`](Install/Install.vdproj), [`alienfx-config.cmd`](alienfx-config.cmd), DPTF `.dvx` hex dump + strings extraction.
3. **Parallel `explore` agents**, four in flight simultaneously:
   - **A** — Network / exfiltration (WinHTTP / WinINet / sockets / DNS / hardcoded URLs / DXGI capture data-flow trace / keyboard hooks / process enumeration / telemetry SDKs / credentials).
   - **B** — Persistence / privilege-escalation (registry hive scope / services / scheduled tasks / autostart / UAC / DLL injection / DLL hijack / driver loading / AWCC tampering / embedded payloads / manifest review).
   - **C** — Obfuscation / dynamic loading / anti-analysis (string obfuscation / dynamic API resolution / anti-debug / anti-VM / shellcode / reflective load / packing / eval-like).
   - **D** — C/C++ memory & resource safety (heap / Win32 handles / GDI / DXGI / COM / FFT / strings / UAF / DF / uninit / error paths / signed-unsigned).
4. **Spot-verification of every Critical/High finding** from the agents against the actual source. Many of agent **D**'s findings did not survive verification; the audit reports only the verified subset.
5. **Independent confirmation** of agent **A**'s "only 2 Internet-API hits in entire codebase" claim via my own `git ls-files | xargs grep` across every C/C++ file.

### 7.2 Appendix B — Rejected agent findings

For transparency, the following automated findings were **rejected** after reading the source:

| Claim | File:Line | Verified actual state |
| --- | --- | --- |
| "Buffer overflow in path operations" | [alienfx-gui.cpp:256](alienfx-gui/alienfx-gui.cpp:256) | Line is `HBRUSH Brush = CreateSolidBrush(...)` inside the `RedrawButton` GDI helper. Nothing to do with file paths. **Fabricated**. |
| "use-after-free: `CloseHandle(devHandle); devHandle = NULL;`" | [AlienFX_SDK.cpp:239](AlienFX-SDK/AlienFX_SDK/AlienFX_SDK.cpp:239) | This is the standard correct close-then-null pattern. Setting to `NULL` after `CloseHandle` is defensive; a later read would NULL-deref, not UAF. **False positive**. |
| "wchar→char overflow at description build" | [AlienFX_SDK.cpp:246–251](AlienFX-SDK/AlienFX_SDK/AlienFX_SDK.cpp:246) | `descbuf` is a fixed `wchar_t[256]` stack array filled by `HidD_GetManufacturerString(..., 255)` (null-terminated by contract); the receiver `description` is a `std::string` that auto-grows. Only side-effect is silent Unicode→Latin1 truncation for non-Latin1 manufacturer names (data fidelity, not safety). **False positive**. |
| "`delete[] deviceInterfaceDetailData` not on all paths" | [AlienFX_SDK.cpp:183](AlienFX-SDK/AlienFX_SDK/AlienFX_SDK.cpp:183) | `delete[]` at [line 256](AlienFX-SDK/AlienFX_SDK/AlienFX_SDK.cpp:256) is OUTSIDE the `if` block — runs on all paths. **False positive**. |
| "`HidD_FreePreparsedData` not on all paths" | [AlienFX_SDK.cpp:194](AlienFX-SDK/AlienFX_SDK/AlienFX_SDK.cpp:194) | `HidD_FreePreparsedData(prep_caps)` at [line 194](AlienFX-SDK/AlienFX_SDK/AlienFX_SDK.cpp:194) runs unconditionally after `HidP_GetCaps`. **False positive**. |
| "Wrong cleanup function `DeleteDC` for `GetDC` handle" | [HapticsDialog.cpp:87](alienfx-gui/HapticsDialog.cpp:87) | `ReleaseDC` at [line 86](alienfx-gui/HapticsDialog.cpp:86) already correctly cleans up the handle; the extra `DeleteDC` is **redundant** but not the catastrophic "wrong-API-on-handle" bug originally claimed. Downgraded from Critical to Low (see M1). |
| "GDI object selection leak — `hOld` not restored" | [HapticsDialog.cpp:48–49](alienfx-gui/HapticsDialog.cpp:48) | `hOld = SelectObject(hdc, hbmMem)` at [line 36](alienfx-gui/HapticsDialog.cpp:36) and `SelectObject(hdc, hOld)` at [line 82](alienfx-gui/HapticsDialog.cpp:82) — correctly saved/restored. **False positive**. |
| "`delete[] imgz` on uninitialized pointer if `needLightsUpdate==false`" | [CaptureHelper.cpp:105](alienfx-gui/CaptureHelper.cpp:105) | `imgz` is default-NULL-initialized in [CaptureHelper.h:23](alienfx-gui/CaptureHelper.h:23) (`byte *imgz = NULL`). `delete[] nullptr` is a well-defined no-op. **False positive**. |
| "`kiss_fft_free` not called if thread exits early" | [WSAudioIn.cpp:268–269](alienfx-gui/WSAudioIn.cpp:268) | There is no early `return` inside the `FFTProc` while loop; cleanup at lines 266–269 always runs when the loop exits via the `stopEvent`. **False positive**. |
| "Integer underflow in `new DWORD[maxProcess >> 2]`" | [EventHandler.cpp:239](alienfx-gui/EventHandler.cpp:239) | `EnumProcesses` takes a buffer size in **bytes**; `>> 2` divides by `sizeof(DWORD)` to get the correct element count. Math is correct. **False positive**. |
| "PowerShell scheduled-task creation is suspicious" | [Common.cpp:193](Common/Common.cpp:193) | Plaintext `Register-ScheduledTask -TaskName ... -RunLevel Highest`, gated on user opt-in, only auto-starts the same executable. Documented. Re-classified as benign. |

---

## 8. Remediation Log

All six verified [§5 Memory & Resource Safety](#5--findings--memory--resource-safety) findings (M1–M6) were fixed in a follow-up pass after the audit. Diff statistics:

```
 Common/Common.cpp             |  9 +++++----
 LightFX/LightFX.cpp           | 30 +++++++++++++++++++++++++++++-
 alienfx-gui/HapticsDialog.cpp |  1 -
 alienfx-gui/WSAudioIn.cpp     | 18 ++++++++++--------
 4 files changed, 44 insertions(+), 14 deletions(-)
```

### 8.1 Per-finding remediation

| # | Original file:line | Status | What changed | Notes |
| --- | --- | --- | --- | --- |
| M1 | [HapticsDialog.cpp:87](alienfx-gui/HapticsDialog.cpp:87) | **Fixed** | Removed the redundant `DeleteDC(hdc_r);`. The preceding `ReleaseDC(hysto, hdc_r);` already correctly returns the window DC. | Exactly the audit-stated fix. |
| M2 | [WSAudioIn.cpp:123](alienfx-gui/WSAudioIn.cpp:123) | **Fixed** | Changed `IMMDeviceEnumerator* pEnumerator;` → `IMMDeviceEnumerator* pEnumerator = NULL;`. | Exactly the audit-stated fix. The subsequent `if (pEnumerator)` check is now safe on `CoCreateInstance` failure. |
| M3 | [LightFX.cpp:206](LightFX/LightFX.cpp:206) | **Fixed (scope expanded vs audit)** | Replaced bare `return LFX_ERROR_NODEVS;` with a full teardown block: stop the worker thread (`SetEvent(stopQuery)` + `WaitForSingleObject` + `CloseHandle`), close `stopQuery` and `haveNewElement`, then `delete afx_dev; afx_dev = NULL;`. | **Expanded vs audit-stated fix.** The audit's stated minimum fix was `delete afx_dev; afx_dev = NULL;` only — but `CLightsProc` at [LightFX.cpp:54](LightFX/LightFX.cpp:54) dereferences `afx_dev` with no NULL guard, so the audit's stated fix would have introduced a use-after-free crash on the worker thread's next iteration. Verified by reading CLightsProc body. The expanded fix mirrors the existing `LFX_Release` shutdown sequence ([LightFX.cpp:237–251](LightFX/LightFX.cpp:237)) and adds an inline comment pointing to the line-54 invariant so future maintainers don't "simplify" it back into the UAF. |
| M4 | [LightFX.cpp:174–176](LightFX/LightFX.cpp:174) | **Fixed** | After `updateThread = CreateThread(...)`, added an `if (!updateThread)` check that closes `stopQuery` + `haveNewElement`, NULLs them, frees `afx_dev`, and returns `LFX_ERROR_NOINIT`. | Audit-stated fix plus the same `delete afx_dev; afx_dev = NULL;` symmetry as M3 — without it, a `CreateThread` failure would leave `afx_dev` orphaned and the next `LFX_Initialize` call would skip re-allocation, then crash inside the worker code that needs it. |
| M5 | [WSAudioIn.cpp:210–213](alienfx-gui/WSAudioIn.cpp:210) | **Fixed** | (a) `#include <memory>` added. (b) The three `new T[NUMPTS]` allocations replaced with `std::unique_ptr<T[]>(new T[NUMPTS])`. (c) `kiss_fftr_alloc` moved AFTER the unique_ptrs and now returns early on NULL (kiss_fft documents it returns NULL on failure; original code crashed on the subsequent `kiss_fftr(NULL, ...)`). (d) `kiss_fftr(...)` call updated to `padded_in.get()` / `padded_out.get()`. (e) The three matching `delete[]` lines at end-of-function removed; `kiss_fft_free(kiss_cfg);` retained. | All four allocations are now exception-safe. Reordering (kiss_cfg last) means a `bad_alloc` in any `new[]` can't leak a kiss_cfg config. |
| M6 | [Common.cpp:142,180](Common/Common.cpp:142) | **Fixed** | (a) `#include <memory>` added. (b) `char* buf = new char[255];` → `unique_ptr<char[]> buf(new char[255]);` (relying on the file's existing `using namespace std;`). (c) The `delete[] buf;` at end-of-function removed. (d) Two raw-pointer use sites updated to `.get()` where the API takes `char*`: `InternetReadFile(req, buf.get(), 254, ...)` and `string res = buf.get();`. Indexing `buf[byteRead] = 0;` unchanged (unique_ptr exposes `operator[]`). | Exception-safe against the `std::string` ops between `new` and `delete[]` that could throw on OOM. |

### 8.2 Build & functional impact

- **No behavioral change in the success path.** The only observable changes are on failure paths (OOM, `CoCreateInstance` failure, `kiss_fftr_alloc` failure, `CreateThread` failure, and the LightFX "no Alienware hardware present" path).
- **No public API changes.** Function signatures, exported entry points, and ABI all unchanged.
- **No new dependencies.** Both new `#include <memory>` lines are STL — no third-party additions, no new libs to link.
- **Build environment unchanged.** Visual Studio 2019 / 2026 with the default C++14+ standard is sufficient for `std::unique_ptr<T[]>` constructor syntax. Confirmed compatible per [README:84](README.md#L84).
- **LSP diagnostics not run** for these changes — `clangd` on Linux cannot resolve `<windows.h>` / `<WinInet.h>` / `<Audioclient.h>` / `<Mmdeviceapi.h>` / `<kiss_fftr.h>`, so any diagnostics it produced would be misleading noise. Verification was instead done by (a) reading every modified region back after the edit, (b) confirming the diff matches the planned changes line-by-line, and (c) confirming no collateral changes via `git diff --stat`. Final compile verification should be done in Visual Studio on Windows.
- **Comments added** at five sites explaining the security/correctness rationale for the four non-trivial patterns (`std::unique_ptr` in an otherwise raw-pointer codebase × 2, `CreateThread` rollback, `CLightsProc` `afx_dev` invariant). Without them, a future maintainer "modernizing for consistency with the surrounding code" could re-introduce the bugs.

### 8.3 Files touched (final)

| File | Lines added | Lines removed |
| --- | --- | --- |
| [Common/Common.cpp](Common/Common.cpp) | +5 | -4 |
| [LightFX/LightFX.cpp](LightFX/LightFX.cpp) | +29 | -1 |
| [alienfx-gui/HapticsDialog.cpp](alienfx-gui/HapticsDialog.cpp) | 0 | -1 |
| [alienfx-gui/WSAudioIn.cpp](alienfx-gui/WSAudioIn.cpp) | +10 | -8 |

No source file outside this list was modified.

---

*End of audit. Original analysis recorded above (§§0–7); remediation log (§8) added after the M1–M6 fixes were applied to the four files listed in §8.3.*
