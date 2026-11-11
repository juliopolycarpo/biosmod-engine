# Desktop interface on Linux

English | [Brazilian Portuguese](../pt-BR/guide/gui.md)

`bme-gui` is a desktop client for `bme`. It reads firmware images and creates new output files. Only its **Flash chip** page accesses a flash chip, through `bme flash` and flashrom. The GUI runs every request offline except **Download and install** on the Sources & tools page, which fetches the pinned Ghidra. Verification checks the image offline and does not establish boot safety, physical board compatibility or acceptance by platform signature enforcement.

## Build and run

Linux x86_64 is the first GUI target. The GUI requires Rust 1.92 or newer; core and CLI retain their Rust 1.88 minimum. Build both executables together:

```sh
cargo build --locked --release -p biosmod-cli -p biosmod-gui
target/release/bme-gui
```

The GUI looks for `bme` beside its executable. To use another installation, choose it under **Settings**, or launch `bme-gui --engine /absolute/path/to/bme`. An override must pass the protocol handshake and advertise both `desktop_workflow: 1` and `direct_patch_workflow: 1`; an older binary with the same package version is insufficient. No engine is loaded from an image or catalog directory.

The build uses Slint 1.18.1 with the winit backend and GPU and software renderers. The GUI links fontconfig, FreeType, libgcc and glibc. The desktop also needs fonts, XKB, and Wayland or X11 client libraries; GPU rendering additionally needs a working OpenGL/EGL stack. Some windowing and graphics libraries are loaded dynamically. Native file dialogs use the XDG desktop portal and a portal backend. Manual path entry remains available if the portal is unavailable. To force software rendering, run:

```sh
SLINT_BACKEND=winit-software target/release/bme-gui
```

CI targets Ubuntu 24.04 x86_64 (glibc 2.39) for the archive and exercises separate X11 and headless Wayland connections. The [Linux desktop qualification report](../linux-desktop-qualification.md) records clean-VM GNOME and Plasma, scaling and screen-reader results for the tested archive and desktop versions. Windows and macOS GUI behavior is not yet qualified.

The window starts at its supported 760×600 minimum so small desktops have room for panels and decorations. Resize it for a larger workspace.

## Linux archive

Build on the intended Ubuntu 24.04 baseline to avoid requiring a newer glibc:

```sh
./packaging/linux/archive.sh
```

The archive in `dist/` contains the matched binaries, a desktop entry, an icon and license notices. Extract it and run `bin/bme-gui`, or copy its `bin/` and `share/` directories into `~/.local/` and ensure `~/.local/bin` is on `PATH`. The archive is not a sandbox and shares the CLI's configuration, cache and catalog sources. The system still supplies graphics, font, keyboard and portal libraries.

The project's code is MIT. The desktop distribution uses the Slint Royalty-free Desktop, Mobile, and Web Applications License 2.0; **About** displays the required AboutSlint widget. The archive contains that license and the collected runtime dependency notices under `share/licenses/biosmod-engine/`.

## Scan, select and build

1. Choose an image, inspect it, choose a catalog source and scan. A board profile identifies catalog information, not the revision or components of a physical board.
2. Select eligible corrections by clicking a finding or pressing Space or Enter. **Recommended** selects the engine's recommended rows when the whole recommendation is eligible. Rows requiring hardware assertions, hold or diagnostic permissions, or joint prerequisite selection cannot be selected here. A missing detection does not prove a defect is absent.
3. Choose an output path and press **Build patched copy**. The default places `.patched` before the input's final extension. Existing image and manifest paths are not overwritten. If the image or catalog changed since the scan, scan again and review the selection.
4. The GUI independently verifies the published output and manifest. It reports completion only when all required checks succeed. A publication failure may leave artifacts; inspect the reported paths. An incomplete verification is not a verified result.

**Preview changes** optionally builds and validates in memory to show component changes and the expected output; it does not publish files or authorize a later build. **Export selection** saves the visible selection to a new recipe file. Both actions use the input and source from the displayed scan.

**Open selection file** loads an exact recipe for replay after validation against the current image, catalog and engine. The GUI retains a private copy and does not let the recipe grant unsupported permissions or switch the selected catalog. A recipe requires its pinned catalog and matching engine build. To reopen an output, choose the original image and output; its manifest must be beside it at `<output>.manifest.json`. An optional selection file can also be used for matching.

**Sources & tools** lists the catalog sources (read-only; use the CLI to register or update them) and one card per external tool: Ghidra, ghidra-firmware-utils, Java, the JDK, git, flashrom and the optional NASM. A card shows the state, version and location. **Download and install** appears only when nothing blocks it (a saved location or a missing JDK or git does; the card says what to do first) and fetches the pinned Ghidra with the checks `bme tools setup ghidra` makes; it takes minutes and can be cancelled. **Choose location…** saves an existing Ghidra folder or flashrom program, and **Reset** forgets it. For Java, git and flashrom the card shows the package-manager command to run yourself. The GUI never runs `sudo`.

## Flash chip

The **Flash chip** page works on Linux with flashrom installed and an engine that advertises `flash_workflow: 1`. `bme guide flashing` explains each step and its refusals.

1. Enter a flashrom programmer (`internal` for this machine, `ch341a_spi` for a CH341A) and press **Diagnose**. The report lists the board, the matching catalog board profile and what helps or blocks chip access.
2. **Find chip** names the chip. If several definitions match, use the CLI with `--chip`; the page has no chip field.
3. Choose a new backup file with **New…** and press **Back up chip**. The chip is read twice; existing files are not overwritten.
4. Build a patched copy from that backup on the Workflow page. **Flash this output…** on the results view carries the output over as the image.
5. **Check** compares the chip with the backup and lists the regions and the number of bytes that will change. Nothing is written. **Whole chip** is for chips without an Intel flash descriptor.
6. Tick the recovery confirmation and press **Flash chip**. The write repeats exactly the checked programmer, image and backup; editing any of them requires a new check. The chip is read back afterwards.

With **Ask for administrator rights** ticked, Find chip, Back up chip, Check and Flash chip run `bme` through `pkexec`, which shows the desktop's authentication dialog. Untick it when the GUI already runs with access to the programmer, for example through udev rules for a USB programmer. Diagnose never asks; run `sudo bme flash doctor` to include the BIOS write-protection bits.

Backup, check and write cannot be cancelled, and the window stays open until they finish. If a write fails after it started, the status says the chip may hold a partial image: keep the board powered and follow `bme guide recovery`.

## Settings and diagnostics

The default theme follows the desktop and falls back to light. **Settings** also offers explicit light and dark choices. The language selector offers English (the default) and Português (Brasil); changes apply immediately and are saved with the other preferences. Application-owned text follows this choice; native file-picker controls may follow the desktop language. Engine diagnostics and catalog text remain in their original language. Theme, language and engine-path preferences are stored in `$BME_CONFIG_HOME/gui.json` when `BME_CONFIG_HOME` is set, otherwise in `$XDG_CONFIG_HOME/biosmod-engine/gui.json` or `~/.config/biosmod-engine/gui.json`. Empty overrides and relative XDG paths are ignored. Relative `BME_*_HOME` overrides resolve against the GUI startup directory and are passed as absolute paths to the engine. Engine edits invalidate the previous connection immediately; the preference is saved on Enter or when the field loses focus. Choosing an executable with Browse saves it immediately. Image and output paths are not saved there.

Read-only operations can be cancelled. Building a copy cannot be safely cancelled from the interface; let publication finish. If the process is interrupted externally, check both output paths before trying again. The Diagnostics page can copy or export bounded recent messages. Review those messages for local paths before sharing them.

## Firmware limits

The engine aligns FFS files relative to their volume, so volumes at any image offset parse and reflow. In descriptor images, flash addresses map the end of the BIOS region to 4 GiB. Cataloged ACPI tables at disjoint offsets in one RAW section support same-length edits and independent verification, using GUID, leaf and table offset as their identity ([#36](https://github.com/juliopolycarpo/biosmod-engine/pull/36)). Overlaps and multi-table resizing that could move another table are refused. TE relocation coverage checks remain unsupported and return `FORMAT_UNSUPPORTED`.

When independent verification cannot finish, the CLI reports `VERIFICATION_INCOMPLETE` with the partial report in error details. The GUI keeps incomplete results separate from verified results.

## Validation of the previous interface recorded on 2026-11-09

The real synthetic workflow passed through the controller and through the Slint event loop, including plan export and automatic independent verification. Output bytes and manifest semantics match an equivalent CLI run. Native runs on Ubuntu 26.04/GNOME passed with Wayland software rendering in light and dark themes, Wayland accelerated rendering, and X11 software rendering through XWayland. These are separate from a native Xorg desktop qualification.

Headless callback tests cover enablement, input invalidation, imported plans, publication recovery, cancellation/closure and export. Native AT-SPI inspection found the primary controls and their accessible labels. That check does not establish a complete screen-reader or keyboard-only workflow. Layouts were rendered at 1080×780 and 760×600. After the interface polish, native Wayland software-rendered captures at both sizes in light and dark themes covered every page on the same Ubuntu 26.04/GNOME host; no other desktop was rechecked. Vendor-ROM tests were skipped because no `BME_ROM_*` inputs were configured; no hardware boot test was performed.
