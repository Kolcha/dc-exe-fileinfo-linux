#pragma once
#include "BinaryAnalyzer.h"
namespace fileinfo {
class ElfAnalyzer final : public BinaryAnalyzer {
public:
    AnalysisResult inspect(const fs::path& path) const override;
};
}
