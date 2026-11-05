#pragma once
#include "analysis/DependencyResolver.h"
#include <QWidget>
class QTabWidget;
class QTreeView;
class QTreeWidget;
class QLabel;
namespace fileinfo {
class DependenciesModel;
class SymbolsWidget;
class ViewerWidget final : public QWidget {
public:
    explicit ViewerWidget(QWidget* parent=nullptr);
    bool load(const fs::path& path);
private:
    void populateDependencies();
    QTabWidget* tabs_;
    SymbolsWidget* symbols_;
    QTreeWidget* general_;
    QTreeView* dependencies_;
    QLabel *generalWarning_, *dependencyWarning_;
    AnalysisContext analysis_;
    std::unique_ptr<DependencyResolver> resolver_;
    std::shared_ptr<const AnalysisResult> current_;
    DependenciesModel* model_{};
};
}
