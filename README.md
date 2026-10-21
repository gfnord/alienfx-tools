# Alienware Fan Control

Lightweight fan and power control for Alienware and Dell G-series systems, without AWCC: fan curves driven by any temperature sensor, BIOS power modes and G-Mode, CPU boost mode, TCC/XMP overclocking and a Windows power plan switch.

Usage guide: [Doc/alienfan-gui.md](/Doc/alienfan-gui.md).

## How does it work?

Unlike many other fan control tools (`SpeedFan`, `HWINFO`, `Dell Fan Control`), it does not access or modify the EC (Embedded Controller) directly. It uses the proprietary Alienware function calls in the ACPI BIOS - the same ones AWCC uses.

- It's safer - the BIOS still monitors the fans, so there is no risk of fans stopping under full load.
- It's universal - most Alienware/Dell G-series systems share the same interface.
- In some cases it is the only way - for example, the Alienware m15/m17R1 have no EC control.

## Requirements

- Alienware ACPI BIOS: modern Alienware/Dell G-series notebooks (any m-series, x-series, Area-51m), Aurora R7 and later desktops.
- Windows 10 v1903 or later (64-bit only). Windows 11 supported.
- Administrator rights (needed to talk to the BIOS).

The app connects to GitHub only for the optional update check (`Settings` - `Check for updates`). It does not collect or share any personal data.

## Windows power plan switch

The `Windows power` drop-down switches Windows between four levels: Power saver, Balanced, High Performance and Ultimate Performance. It shows the active level at start and follows changes made outside the app (Control Panel, Settings, `powercfg`). It stays empty if the active plan is not one of the four levels. The label next to it shows which mechanism is used:

- **Power plans** - the level activates the matching built-in plan (matched by GUID, so it works on non-English Windows). If the plan is missing, the app creates it once with `powercfg -duplicatescheme`, reusing an existing plan with the same name if there is one, and stores the new plan GUID in `HKCU\SOFTWARE\Alienfan\PowerPlans`.
- **Power modes (Modern Standby)** - on systems with Modern Standby (S0 Low Power Idle), Windows hides and blocks every plan except Balanced. The app then never creates plans. It activates Balanced and sets the Windows power mode instead: Best power efficiency, Balanced, Better performance or Best performance.

The app never changes `PlatformAoAcOverride` and never turns off Modern Standby - on such hardware this removes Sleep completely. If a switch fails, the drop-down returns to the active level and the error is shown.

## Settings backup

All settings live in `HKCU\SOFTWARE\Alienfan`:

```
reg export HKCU\Software\Alienfan alienfan.reg
reg import alienfan.reg
```

## How to build

Prerequisites: Visual Studio 2026 with the "Desktop development with C++" workload.

Open `alienfx-tools.sln` and build `alienfan-gui` (Release | x64), or from a Developer Command Prompt:

```
msbuild alienfan-tools\alienfan-gui\alienfan-gui.vcxproj -p:Configuration=Release -p:Platform=x64
```

The executable is written to `x64\Release\alienfan-gui.exe`.

## Versioning and releases

Versions are `MAJOR.MINOR.PATCH`. The single source of truth is `FILEVERSION` / `PRODUCTVERSION` (and the matching `FileVersion` / `ProductVersion` strings) in `alienfan-tools/alienfan-gui/alienfan-gui.rc`, stored as four parts (`1.0.0` = `1,0,0,0`).

To release:

1. Bump the version in `alienfan-gui.rc` and commit it.
2. Tag the commit with the same version and push the tag:
   ```
   git tag 1.0.1
   git push origin 1.0.1
   ```
3. The `Release` GitHub Actions workflow checks that the tag matches the version in `alienfan-gui.rc`, builds Release x64 and publishes a GitHub release with `alienfan-gui.exe` attached.

The in-app update check (`Settings` - `Check for updates`) compares the app version with the latest GitHub release of this repository.

## License

MIT. See [LICENSE](/LICENSE).

## Credits

Based on [alienfx-tools](https://github.com/T-Troll/alienfx-tools) by T-Troll - original fan control functionality, SDK and code.  
This repository keeps only the fan control application and adds its own changes (Windows power plan switch, resource-safety fixes).
