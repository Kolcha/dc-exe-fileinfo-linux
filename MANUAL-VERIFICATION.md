# Implementation verification

Built locally with GCC 13.3, CMake, Qt 6.10.2 and libelf 0.190. No dependencies
were installed. The local `dc-torrent-view` integration and Double Commander
source were inspected: Qt host handles are `QWidget*` and the detection parser
supports `[offset]=decimal-byte` comparisons joined by `&`.

Temporary fixture programs and drivers were kept under `/tmp/fileinfo-manual`,
not added as a project test suite. Analysis results were inspected alongside
`readelf` output. WLX exports were invoked from an offscreen Qt application.

| Acceptance case | Result |
| --- | --- |
| ELF64 executable | `/bin/ls`: identity, GNU notes, security and direct declarations checked |
| ELF32 executable | Built a real i386 executable with `as --32` and `ld -m elf_i386`; parsed on AMD64 |
| Shared library | Compiled a shared library with SONAME; also inspected installed dynamically linked libraries |
| Relocatable object | Compiled C object; no dependencies or spurious analysis warnings |
| Static executable | Compiled with `gcc -static`; classified Static |
| Static PIE | Compiled with `gcc -static-pie`; classified Static and PIE despite PT_DYNAMIC |
| Stripped executable | `strip` fixture reports absent static symbol table |
| No section headers | Removed section-table references from a copy of `/bin/ls`; dependencies and notes still present |
| Symlink | Viewer displays original requested path; analysis uses target contents |
| Missing dependency | Synthetic DT_NEEDED entry remains visible with failure diagnostic |
| AArch64 on AMD64 | Synthetic ELF64 AArch64 identity with DT_NEEDED; installed AMD64 candidates rejected (not a runnable ARM fixture) |
| Malformed/truncated | Truncated header, magic-only file and out-of-bounds dynamic string table produce diagnostics |
| Dependency cycle | Synthetic A → B → A graph terminates with a visible blocked node |
| Tree limits | Synthetic chain stops at depth 10; 1,005 declarations show 1,000 nodes and an omission warning |
| ListLoadNext | Reuses widget, resets tab and model, clears data on unrecognized reload |
| Multiple viewers | Independent widgets retain separate metadata when another reloads |

Additional checks covered direct-tab lazy population, deferred child inspection,
RPATH inheritance, RUNPATH not being inherited, copying path spelling through a
symlink reload, WLX detection-buffer bounds, exported symbol visibility, and
recursive inspection of the installed Qt6 Double Commander executable. The
latter's repeated dependency paths correctly reach the tree safety limit.

AddressSanitizer and UndefinedBehaviorSanitizer checks passed for the offscreen
lifecycle/graph driver and representative valid and malformed analysis fixtures.
LeakSanitizer could not run in this execution environment (it reported its
ptrace restriction), so these checks used `ASAN_OPTIONS=detect_leaks=0`.

The offscreen driver checks plugin lifecycle and model behavior. **Actual
embedding, sizing, keyboard navigation, context-menu interaction and appearance
inside a running Double Commander window still require live-host acceptance.**
The implementation uses the reference plugin's embedding convention; no user
Double Commander configuration was modified or plugin installed automatically.
