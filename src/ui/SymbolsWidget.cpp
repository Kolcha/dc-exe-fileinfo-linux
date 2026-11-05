#include "SymbolsWidget.h"
#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QComboBox>
#include <QLineEdit>
#include <QCheckBox>
#include <QLabel>
#include <QHeaderView>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMenu>
#include <QApplication>
#include <QClipboard>
namespace fileinfo {
namespace {
QString q(const std::string& s){return QString::fromUtf8(s.data(),s.size());}
class Model final : public QAbstractTableModel {
public:
    using QAbstractTableModel::QAbstractTableModel;
    SymbolAnalysisResult result;
    bool demangle=true;
    int rowCount(const QModelIndex& p={}) const override {return p.isValid()?0:result.symbols.size();}
    int columnCount(const QModelIndex& ={}) const override{return 6;}
    QVariant headerData(int s,Qt::Orientation o,int role) const override {static const char* names[]={"Symbol","Type","Binding","Version","Address","Size"}; return role==Qt::DisplayRole && o==Qt::Horizontal?QVariant(names[s]):QVariant();}
    QVariant data(const QModelIndex& i,int role) const override {
        if(!i.isValid()) return {};
        const auto& s=result.symbols[i.row()];
        if(role==Qt::UserRole+1) return s.imported;
        if(role==Qt::UserRole+2) return q(s.originalName)+"\n"+q(s.demangledName);
        if(role==Qt::UserRole+3) return q(s.originalName);
        if(role==Qt::ToolTipRole) return q(s.originalName)+"\nVisibility: "+q(s.visibility);
        if(role!=Qt::DisplayRole && role!=Qt::UserRole) return {};
        switch(i.column()) {case 0:return q(demangle?s.demangledName:s.originalName); case 1:return q(s.type); case 2:return q(s.binding); case 3:return (s.imported || s.version.empty()?QString():s.defaultVersion?QString("@@"):QString("@"))+q(s.version); case 4: return role==Qt::UserRole?QVariant::fromValue<qulonglong>(s.value):QVariant("0x"+QString::number(s.value,16)); case 5:return QVariant::fromValue<qulonglong>(s.size); } return {};
    }
    void refresh(){beginResetModel();endResetModel();}
};
class Proxy final : public QSortFilterProxyModel {
public:
    using QSortFilterProxyModel::QSortFilterProxyModel;
    bool imports=false; QString query;
    bool filterAcceptsRow(int row,const QModelIndex& p) const override {auto i=sourceModel()->index(row,0,p); return i.data(Qt::UserRole+1).toBool()==imports && i.data(Qt::UserRole+2).toString().contains(query,Qt::CaseInsensitive);}
    void refresh(){invalidate();}
};
}
class SymbolsWidget::Impl {
public:
    Model* model; Proxy* proxy; QTableView* table; QComboBox* direction; QLineEdit* search; QCheckBox* demangle; QLabel* count; QLabel* warning;
};
SymbolsWidget::SymbolsWidget(QWidget* parent):QWidget(parent),impl_(new Impl) {
    // Keep the small non-QObject holder tied to this widget's lifetime.
    connect(this,&QObject::destroyed,[p=impl_]{delete p;});
    auto& w=*impl_; auto* layout=new QVBoxLayout(this); auto* controls=new QHBoxLayout;
    w.direction=new QComboBox(this); w.direction->addItems({"Exports","Imports"}); w.search=new QLineEdit(this); w.search->setPlaceholderText("Filter symbol names"); w.demangle=new QCheckBox("Demangle",this); w.demangle->setChecked(true);
    controls->addWidget(w.direction); controls->addWidget(w.search,1); controls->addWidget(w.demangle); layout->addLayout(controls);
    w.warning=new QLabel(this); w.warning->setTextFormat(Qt::PlainText); w.warning->setWordWrap(true); layout->addWidget(w.warning);
    w.model=new Model(this); w.proxy=new Proxy(this); w.proxy->setSourceModel(w.model); w.proxy->setSortRole(Qt::UserRole); w.proxy->setSortCaseSensitivity(Qt::CaseInsensitive);
    w.table=new QTableView(this); w.table->setModel(w.proxy); w.table->setSortingEnabled(true); w.table->sortByColumn(0,Qt::AscendingOrder); w.table->setSelectionBehavior(QAbstractItemView::SelectRows); w.table->setSelectionMode(QAbstractItemView::ExtendedSelection); w.table->setEditTriggers(QAbstractItemView::NoEditTriggers); w.table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive); w.table->setColumnWidth(0,420); layout->addWidget(w.table);
    w.count=new QLabel(this); layout->addWidget(w.count);
    auto update=[this]{auto&w=*impl_; w.count->setText(QString("%1 symbols shown / %2 total%3").arg(w.proxy->rowCount()).arg(w.model->rowCount()).arg(w.model->rowCount()?"":" — No dynamic symbols"));};
    connect(w.direction,&QComboBox::currentIndexChanged,this,[this,update](int i){auto&w=*impl_; w.proxy->imports=i==1; w.proxy->refresh(); w.table->setColumnHidden(4,i==1); w.table->setColumnHidden(5,i==1); update();});
    connect(w.search,&QLineEdit::textChanged,this,[this,update](const QString& s){impl_->proxy->query=s; impl_->proxy->refresh(); update();});
    connect(w.demangle,&QCheckBox::toggled,this,[this](bool b){impl_->model->demangle=b; impl_->model->refresh();});
    w.table->setContextMenuPolicy(Qt::CustomContextMenu); connect(w.table,&QWidget::customContextMenuRequested,this,[this](const QPoint& p){auto&w=*impl_; auto i=w.table->indexAt(p); if(i.isValid() && !w.table->selectionModel()->isSelected(i)) w.table->setCurrentIndex(i); QMenu menu(this); auto* copy=menu.addAction("Copy original symbol names"); if(menu.exec(w.table->viewport()->mapToGlobal(p))==copy){QStringList names; for(auto i:w.table->selectionModel()->selectedRows()) names<<i.data(Qt::UserRole+3).toString(); QApplication::clipboard()->setText(names.join('\n'));}});
}
void SymbolsWidget::reset(const fs::path& path){path_=path; loaded_=false; auto&w=*impl_; w.model->result={}; w.model->refresh(); w.search->clear(); w.direction->setCurrentIndex(0); w.demangle->setChecked(true); w.warning->clear(); w.warning->setToolTip({}); w.count->clear(); w.table->clearSelection(); w.table->sortByColumn(0,Qt::AscendingOrder);}
void SymbolsWidget::populate(){if(loaded_) return; loaded_=true; auto&w=*impl_; w.model->result=analyzeSymbols(path_); w.model->refresh(); QStringList diagnostics; for(auto& d:w.model->result.diagnostics) diagnostics<<q(d.message); w.warning->setText(diagnostics.empty()?"":"⚠ Symbol analysis has diagnostics. Hover for details."); w.warning->setToolTip(diagnostics.join('\n')); w.count->setText(QString("%1 symbols shown / %2 total%3").arg(w.proxy->rowCount()).arg(w.model->rowCount()).arg(w.model->rowCount()?"":" — No dynamic symbols"));}
}
