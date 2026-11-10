# Linux desktop qualification

English | [Brazilian Portuguese](pt-BR/linux-desktop-qualification.md)

The PR #47 archive passed the recorded checks on a clean Ubuntu 24.04.5 x86_64 VM on 2026-11-10, at source head `ef16c82119d56b878dee16cab68c12e8c768bf96`. The archive from [CI run 42868520102](https://github.com/juliopolycarpo/biosmod-engine/actions/runs/42868520102) had SHA-256 `c0bbd32ed03ddd011f21e5b89dcc54c058e6d89e8b1e1677c03b16a89ea9d7a7`, verified on host and guest. The VM used QEMU/KVM virtio VGA and Mesa llvmpipe.

| Session | Results |
| --- | --- |
| GNOME 46 Wayland, Mutter | Keyboard workflow, portal, clipboard and Orca passed. At 1920×1440, display scale 1.25 with text scale 1.5 kept the narrow Tools view and footer visible. |
| GNOME 46 Xorg | The same workflow passed. At the 760×600 minimum, text scale 1 → 1.5 → 1 changed client geometry to 1140×900 and back without a panic. Experimental display scale 1.25 with text scale 1.5 kept review and footer visible. |
| Plasma 5.27.11 Wayland, KWin | The same workflow passed. Output scale 1 → 1.25 → 1 kept the software-rendered GUI alive. Explicit Femtovg also survived scale changes and keyboard navigation. |

Each session used the software renderer for the synthetic scan, CX selection, plan, build and automatic independent verification. Physical keyboard events controlled the GUI; AT-SPI observed it. Orca spoke patch state, plan details and verification completion. Portal export, reopen and cancel preserved the imported review and returned focus. Copy replaced a distinct clipboard sentinel, and paste filled a cleared field. Orca also spoke an invalid-path error and, with an eight-second engine delay, one busy and one completion message. Both Wayland sessions used native Wayland connections.

The initial title and footer fit at 1280×800, and keyboard resizing worked in all three sessions. In GNOME Wayland, clean Tools showed `TOOL_UNAVAILABLE` and the configuration, cache and data paths; switching to Portuguese changed the cached heading from Paths to Caminhos without another tools request. On KDE, the desktop General font was set to Noto Sans 15 pt and the app remained usable; Slint's inheritance of that font setting was not established.

`ldd` resolved the paired binaries. Rust, Cargo, Ghidra and Java were absent from `PATH` during runtime checks. Femtovg used Mesa llvmpipe and emitted EGL DRI2 warnings while remaining responsive; no physical GPU was tested. Orca recordings came from a PipeWire monitor; physical audio playback was not tested. No firmware was flashed or booted, and offline verification does not establish hardware boot safety. These results apply to the tested archive and named desktop versions.

## Repeat the synthetic workflow

Extract the archive and enter its root directory in a graphical session. Create an isolated local catalog and image without network access:

```sh
qualification_root=$(mktemp -d)
export BME_CONFIG_HOME="$qualification_root/config" BME_CACHE_HOME="$qualification_root/cache" BME_DATA_HOME="$qualification_root/data"
./bin/bme dev synthetic -o "$qualification_root/fixture"
./bin/bme catalog add lab "$qualification_root/fixture/catalog" --allow-unsigned-local
SLINT_BACKEND=winit-software ./bin/bme-gui "$qualification_root/fixture/synthetic.bin"
```

Inspect the image and scan with the `lab` source, select CX, review the plan and build to a fresh output path. Confirm **Offline verification complete**. Delete `$qualification_root` after the run.
