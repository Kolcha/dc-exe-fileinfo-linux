#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace fileinfo {
namespace fs = std::filesystem;
enum class BinaryFormat { Unknown, ELF, PE };
enum class AnalysisStatus { Unrecognized, Complete, Partial, Unsupported, Error };
enum class DiagnosticSeverity { Warning, Error };
struct Diagnostic { DiagnosticSeverity severity; std::string message; };
struct Property { std::string name, value; };
struct PropertyGroup { std::string title; std::vector<Property> properties; };
struct Dependency { std::string name; };
struct ElfIdentity {
    unsigned char elfClass{}, encoding{}, osAbi{}, abiVersion{};
    std::uint16_t machine{}, type{};
    std::uint32_t flags{};
};
struct ElfLinking {
    ElfIdentity identity;
    // optional distinguishes an absent tag from an explicitly empty search path.
    std::optional<std::string> rpath, runpath;
    bool noDefaultLib{};
};
struct AnalysisResult {
    BinaryFormat format{BinaryFormat::Unknown};
    AnalysisStatus status{AnalysisStatus::Unrecognized};
    fs::path path;
    std::uintmax_t size{};
    std::string kind;
    std::vector<PropertyGroup> groups;
    std::vector<Dependency> dependencies;
    std::vector<Diagnostic> diagnostics;
    std::optional<ElfLinking> elf;
};
}
