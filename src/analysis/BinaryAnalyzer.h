#pragma once
#include "BinaryTypes.h"
#include <memory>
namespace fileinfo {
class BinaryAnalyzer {
public:
    virtual ~BinaryAnalyzer() = default;
    virtual AnalysisResult inspect(const fs::path& path) const = 0;
};
bool isElf(const fs::path& path);
std::optional<ElfIdentity> readElfIdentity(const fs::path& path);
// Recognition is independent of extension and permissions. Unknown formats have no analyzer.
std::unique_ptr<BinaryAnalyzer> createAnalyzer(const fs::path& path);
AnalysisResult inspectBinary(const fs::path& path);
}
