#pragma once
#include "BinaryAnalyzer.h"
#include <map>
#include <unordered_map>
namespace fileinfo {
struct SearchContext {
    // Already expanded at the defining object's location; nearest ancestor first.
    std::vector<fs::path> inheritedRpaths;
};
enum class ResolutionStatus { Found, NotFound, Incompatible, Error };
struct ResolutionResult {
    ResolutionStatus status{ResolutionStatus::NotFound};
    fs::path path;
    std::string diagnostic;
};
fs::path canonicalKey(const fs::path& path);
class AnalysisContext {
public:
    std::shared_ptr<const AnalysisResult> inspect(const fs::path& path);
    void clear() { cache_.clear(); }
private:
    std::map<fs::path, std::shared_ptr<const AnalysisResult>> cache_;
};
class DependencyResolver {
public:
    DependencyResolver();
    ResolutionResult resolve(const Dependency& dependency, const AnalysisResult& requester, const SearchContext& context);
    SearchContext childrenContext(const AnalysisResult& requester, const SearchContext& context) const;
    const std::string& cacheDiagnostic() const { return cacheDiagnostic_; }
private:
    std::unordered_map<std::string, std::vector<fs::path>> linkerCache_;
    std::string cacheDiagnostic_;
};
}
