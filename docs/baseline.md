# Baseline measurements

English | [Brazilian Portuguese](pt-BR/baseline.md)

Recorded 2026-11-08 to compare later changes against. These are single-machine numbers, not performance claims.

| Item | Value |
|---|---|
| Machine | Intel Xeon E5-2680 v4, Linux x86_64 |
| Toolchain | rustc 1.99.1, release profile (fat LTO, one codegen unit, `panic = abort`, stripped) |
| Executable | 5,253,432 bytes |
| Features | clap (derive, help, usage, suggestions), ureq with rustls and bundled roots, zip (deflate), minisign-verify, toml, liblzma (static, bundled xz 5.8), embedded official catalog and Ghidra scripts |
| `bme version` | under 0.01 s, about 4 MiB peak RSS |
| `bme scan` on the 16 MiB MR9A stock dump | 0.33-0.36 s, about 32 MiB peak RSS |
| `bme patch` stage 2 (B05 B10 B11 R01, reflow and LZMA re-encode) | 0.82 s, about 71 MiB peak RSS |

Measured with `/usr/bin/time -f "%e s %M KiB"`, warm cache, best of three for scan.
