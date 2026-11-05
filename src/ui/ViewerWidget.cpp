#include "ViewerWidget.h"
#include "DependenciesModel.h"
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QLabel>
#include <QMenu>
#include <QTabWidget>
#include <QTreeView>
#include <QTreeWidget>
#include <QVBoxLayout>
namespace fileinfo {
namespace {
QString q(const std::string& s) { return QString::fromStdString(s); }
QLabel* warning(QWidget* parent) {
    auto* label=new QLabel(parent); label->setWordWrap(true); label->setTextFormat(Qt::PlainText);
    label->setTextInteractionFlags(Qt::TextSelectableByMouse); label->setAccessibleName("Analysis diagnostics"); label->hide(); return label;
}
void showWarning(QLabel* label,const QString& text) {
    label->setText("⚠ Analysis has diagnostics. Hover here for details.");
    label->setToolTip(text); label->setAccessibleDescription(text); label->show();
}
}
ViewerWidget::ViewerWidget(QWidget* parent) : QWidget(parent) {
    auto* layout=new QVBoxLayout(this); layout->setContentsMargins(0,0,0,0);
    tabs_=new QTabWidget(this); layout->addWidget(tabs_);
    auto* generalPage=new QWidget(tabs_); auto* gl=new QVBoxLayout(generalPage);
    generalWarning_=warning(generalPage); gl->addWidget(generalWarning_);
    general_=new QTreeWidget(generalPage); general_->setColumnCount(2); general_->setHeaderLabels({"Property","Value"});
    general_->setSelectionMode(QAbstractItemView::ExtendedSelection); general_->setSelectionBehavior(QAbstractItemView::SelectRows);
    general_->setEditTriggers(QAbstractItemView::NoEditTriggers); general_->header()->setSectionResizeMode(0,QHeaderView::ResizeToContents);
    gl->addWidget(general_); tabs_->addTab(generalPage,"General");
    auto* depPage=new QWidget(tabs_); auto* dl=new QVBoxLayout(depPage);
    dependencyWarning_=warning(depPage); dl->addWidget(dependencyWarning_);
    dependencies_=new QTreeView(depPage); dependencies_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    dependencies_->setEditTriggers(QAbstractItemView::NoEditTriggers); dependencies_->setUniformRowHeights(true);
    dl->addWidget(dependencies_); tabs_->addTab(depPage,"Dependencies");
    connect(tabs_,&QTabWidget::currentChanged,this,[this](int tab){ if(tab==1) populateDependencies(); });
    general_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(general_,&QWidget::customContextMenuRequested,this,[this](const QPoint& point){
        QMenu menu(this); auto* copy=menu.addAction("Copy selected properties");
        if(menu.exec(general_->viewport()->mapToGlobal(point))==copy) {
            QStringList rows;
            for(auto* item:general_->selectedItems()) rows << item->text(0)+"\t"+item->text(1);
            QApplication::clipboard()->setText(rows.join('\n'));
        }
    });
    dependencies_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(dependencies_,&QWidget::customContextMenuRequested,this,[this](const QPoint& point){
        if(!model_) return;
        const auto clicked=dependencies_->indexAt(point);
        if(clicked.isValid() && !dependencies_->selectionModel()->isSelected(clicked)) dependencies_->setCurrentIndex(clicked);
        QMenu menu(this); auto* names=menu.addAction("Copy library names"); auto* paths=menu.addAction("Copy resolved paths"); menu.addAction("Copy names and paths");
        const auto* chosen=menu.exec(dependencies_->viewport()->mapToGlobal(point));
        if(!chosen) return;
        QStringList rows;
        for(const auto& index:dependencies_->selectionModel()->selectedRows()) {
            auto name=index.data().toString(); auto path=index.siblingAtColumn(1).data().toString();
            rows << (chosen==names ? name : chosen==paths ? path : name+"\t"+path);
        }
        QApplication::clipboard()->setText(rows.join('\n'));
    });
}
bool ViewerWidget::load(const fs::path& path) {
    tabs_->setCurrentIndex(0);
    dependencies_->setModel(nullptr); delete model_; model_=nullptr;
    resolver_.reset(); current_.reset(); analysis_.clear();
    general_->clear(); generalWarning_->clear(); generalWarning_->setToolTip({}); generalWarning_->setAccessibleDescription({}); generalWarning_->hide();
    dependencyWarning_->clear(); dependencyWarning_->setToolTip({}); dependencyWarning_->setAccessibleDescription({}); dependencyWarning_->hide();
    // Keep the originally requested spelling in General even when analysis caches canonical paths.
    current_=analysis_.inspect(path);
    for(const auto& group:current_->groups) {
        auto* heading=new QTreeWidgetItem(general_,{q(group.title)});
        auto font=heading->font(0); font.setBold(true); heading->setFont(0,font);
        for(const auto& property:group.properties) {
            auto* row=new QTreeWidgetItem(heading,{q(property.name),q(property.value)});
            row->setToolTip(0,q(property.name)); row->setToolTip(1,q(property.value));
        }
        heading->setExpanded(true);
    }
    QStringList diagnostics;
    for(const auto& diagnostic:current_->diagnostics) diagnostics << q(diagnostic.message);
    if(!diagnostics.empty()) showWarning(generalWarning_,diagnostics.join('\n'));
    return current_->status!=AnalysisStatus::Unrecognized;
}
void ViewerWidget::populateDependencies() {
    if(model_ || !current_) return;
    resolver_=std::make_unique<DependencyResolver>();
    if(!resolver_->cacheDiagnostic().empty()) showWarning(dependencyWarning_,q(resolver_->cacheDiagnostic()));
    model_=new DependenciesModel(analysis_,*resolver_,current_,this);
    model_->reportWarning=[this](const QString& text) {
        auto details=dependencyWarning_->toolTip();
        if(details.size()<32768) details += (details.isEmpty() ? "" : "\n\n")+text;
        showWarning(dependencyWarning_,details);
    };
    dependencies_->setModel(model_);
    dependencies_->header()->setSectionResizeMode(0,QHeaderView::ResizeToContents);
    dependencies_->header()->setStretchLastSection(true);
    model_->fetchMore({});
}
}
