# Medições de referência

[English](../baseline.md) | Português (Brasil)

Registradas em 2026-11-08 para comparação com alterações futuras. São medições de uma única máquina, não garantias de desempenho.

| Item | Valor |
|---|---|
| Máquina | Intel Xeon E5-2680 v4, Linux x86_64 |
| Ferramentas | rustc 1.99.1, perfil release (fat LTO, uma unidade de geração de código, `panic = abort`, símbolos removidos) |
| Executável | 5.253.432 bytes |
| Recursos | clap (derive, help, usage, suggestions), ureq com rustls e certificados raiz incluídos, zip (deflate), minisign-verify, toml, liblzma (estático, xz 5.8 incluído), catálogo oficial e scripts Ghidra incorporados |
| `bme version` | menos de 0,01 s, cerca de 4 MiB de pico de RSS |
| `bme scan` no dump original de 16 MiB do MR9A | 0,33–0,36 s, cerca de 32 MiB de pico de RSS |
| `bme patch` estágio 2 (B05 B10 B11 R01, reorganização e recodificação LZMA) | 0,82 s, cerca de 71 MiB de pico de RSS |

Medição com `/usr/bin/time -f "%e s %M KiB"`, cache aquecido e melhor de três execuções para scan.
