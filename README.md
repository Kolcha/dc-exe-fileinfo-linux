# Binary FileInfo for Double Commander

A Linux WLX viewer for ELF executable files, shared libraries and relocatable
objects. The General tab shows grouped identity, linking, build and security
properties. The Dependencies tab displays declared `DT_NEEDED` libraries and
lets you expand their dependencies on demand.

Files are recognized by magic bytes, regardless of extension or executable bits.
Both ELF32 and ELF64 are supported, including binaries without section headers.
Malformed files show diagnostics and available partial metadata without modal
dialogs. ELF core dumps are recognized but unsupported. PE support is planned;
the analysis API is independent of the UI and WLX integration.

## Requirements and build

- Linux (Ubuntu 24.04 or newer).
- A C++20 compiler, CMake 3.20+, and pkg-config.
- Qt **6.7 or newer**, with Widgets development files.
- elfutils libelf development files.
- Double Commander built with **Qt6**, using a compatible Qt runtime.

Development package names on Ubuntu are `build-essential`, `cmake`, `pkg-config`,
`qt6-base-dev`, and `libelf-dev`. Stock Ubuntu 24.04's Qt 6.4 packages do **not**
satisfy the minimum version; use an environment with suitable packaged Qt6
libraries that also match your Double Commander build. GTK and Qt5 builds of
Double Commander are unsupported.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

The plugin is `build/file_info_qt6.wlx`. The bundled `sdk/` contains the Double
Commander plugin headers. No SDK download or extra source library is needed.
Only the four implemented WLX entry points are exported.

For standalone manual inspection:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_DEMO_VIEWER=ON
cmake --build build --parallel
./build/file_info /bin/ls
```

For multiple Qt installations, set `CMAKE_PREFIX_PATH` when configuring and ensure
the host and plugin load compatible libraries. Do not mix Qt toolkit versions.

## Installation and use

Keep `file_info_qt6.wlx` in a persistent directory. In Double Commander, open
**Configuration → Options → Plugins → Viewer plugins (.WLX)**, choose **Add**,
and select the plugin. Enable it and place it ahead of other viewers that match
ELF files. Open an ELF file with the internal viewer (F3).

Optional staged installation is supported with `cmake --install build --prefix
/path/to/staging`; this places the plugin under
`lib/doublecmd/plugins/wlx/file_info`. Register that file in Double Commander as
above. CMake does not edit your Double Commander configuration.

Select properties and use their context menu to copy names and values.
The Dependencies context menu copies library names, resolved paths, or both.
Hover warning icons or the tab's warning indicator for diagnostic details.

Switching to Dependencies resolves direct declarations synchronously. Expanding
a library parses its metadata and resolves its children. A resolved node that
has not been expanded is explicitly marked as not yet analyzed in its tooltip.
Duplicate dependencies can appear under different parents. Cycles are detected
by canonical paths along the ancestor chain. Expansion stops at depth 10 and
1,000 total dependency nodes, with warnings when inspection is limited.

Every viewer owns its own canonical-path metadata cache and linker-cache
snapshot. Loading any file, including the same file again, clears the previous
metadata, tree and cache and selects General. Files are not monitored for changes.

## Dependency resolution

The viewer never executes the inspected file and never uses `ldd`.
Resolution is a best-effort description of possible installed dependencies,
**not a guarantee that the binary can run**.

For names without a slash, resolution considers the requesting object's RPATH
and inherited ancestor RPATHs when it has no RUNPATH, then its RUNPATH, then
system linker-cache entries, then standard architecture-specific directories.
RUNPATH applies only to direct requests; RPATH can be inherited. `$ORIGIN` and
`${ORIGIN}` are expanded relative to the defining object's canonical directory.
An explicit empty search-path component means the viewer process's working
directory. A dependency containing a slash is treated as a pathname.

The system cache is obtained from a fixed system `ldconfig -p` executable without
a shell. Missing utilities, unexpected output, excessive output, or a timeout
produce a warning and leave the other search methods available. `DF_1_NODEFLIB`
is honored for standard-directory candidates. Candidate ELF headers are checked
for class, byte order, machine, OS ABI/version, object type and relevant ARM,
MIPS, RISC-V, PowerPC64 and LoongArch ABI flags before acceptance. Full dependency
metadata is read only when a library node is expanded.

`LD_LIBRARY_PATH`, `LD_PRELOAD`, `LD_AUDIT`, `$LIB`, `$PLATFORM`, glibc hardware
capability selection, symbol versions, runtime symbol lookup and `dlopen()`
discovery are not modeled. Search components containing unsupported tokens are
skipped. Resolution uses the host filesystem; no configurable sysroot is exposed.
Cross-architecture declarations remain visible even when compatible libraries
are unavailable. Linker-cache ordering is used as supplied, without emulating
all loader policy. Partial metadata and safety limits can also restrict results.

## Analysis limits

Stripped/debug status is conservative when section headers are unavailable.
`ET_DYN` alone does not establish that an object is a shared library or executable,
and a dynamic segment alone does not establish external dynamic linking.
Security properties describe ELF declarations rather than runtime guarantees.

Parsing validates file bounds and caps program headers, dynamic entries, strings,
notes, section counts and reported diagnostics to bound work on malformed input.
All inspection and resolution run synchronously. There is no export function,
symbol/disassembly browser, file monitoring, or cache shared across viewers.

No automated test suite or test framework is included. See
[manual verification notes](MANUAL-VERIFICATION.md) for the checks performed and
the remaining live-host acceptance check.
