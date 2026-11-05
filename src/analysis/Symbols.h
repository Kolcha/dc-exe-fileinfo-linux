#pragma once
#include "BinaryTypes.h"
namespace fileinfo {
struct DynamicSymbol {
    std::string originalName, demangledName, type, binding, visibility, version;
    bool imported{}, defaultVersion{};
    std::uint64_t value{}, size{};
    std::uint32_t symbolIndex{};
};
struct SymbolAnalysisResult {
    std::vector<DynamicSymbol> symbols;
    std::vector<Diagnostic> diagnostics;
    AnalysisStatus status=AnalysisStatus::Complete;
};
SymbolAnalysisResult analyzeSymbols(const fs::path& path);
}
