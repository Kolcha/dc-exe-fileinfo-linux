#include "DependenciesModel.h"
#include <QApplication>
#include <QStyle>
#include <algorithm>
namespace fileinfo {
namespace { QString q(const std::string& s) { return QString::fromStdString(s); } }
DependenciesModel::DependenciesModel(AnalysisContext& analysis,DependencyResolver& resolver,std::shared_ptr<const AnalysisResult> root,QObject* parent)
    : QAbstractItemModel(parent),analysis_(analysis),resolver_(resolver) {
    root_.analysis=std::move(root); root_.path=root_.analysis->path; root_.canonical=canonicalKey(root_.path);
}
DependenciesModel::Node* DependenciesModel::node(const QModelIndex& index) const { return index.isValid() ? static_cast<Node*>(index.internalPointer()) : const_cast<Node*>(&root_); }
QModelIndex DependenciesModel::index(int row,int column,const QModelIndex& parent) const {
    if(row<0 || column<0 || column>=2 || (parent.isValid() && parent.column()!=0)) return {};
    auto* n=node(parent);
    if(static_cast<std::size_t>(row)>=n->children.size()) return {};
    return createIndex(row,column,n->children[row].get());
}
QModelIndex DependenciesModel::parent(const QModelIndex& index) const {
    if(!index.isValid()) return {};
    auto* p=node(index)->parent;
    if(!p || p==&root_) return {};
    const auto& siblings=p->parent->children;
    for(std::size_t i=0;i<siblings.size();++i) if(siblings[i].get()==p) return createIndex(static_cast<int>(i),0,p);
    return {};
}
int DependenciesModel::rowCount(const QModelIndex& parent) const { return parent.isValid() && parent.column()!=0 ? 0 : static_cast<int>(node(parent)->children.size()); }
QVariant DependenciesModel::headerData(int section,Qt::Orientation orientation,int role) const {
    if(orientation==Qt::Horizontal && role==Qt::DisplayRole) return section==0 ? "Library" : "Resolved path";
    return {};
}
QVariant DependenciesModel::data(const QModelIndex& index,int role) const {
    if(!index.isValid()) return {};
    const auto* n=node(index);
    if(role==Qt::DisplayRole) return index.column()==0 ? q(n->name) : q(n->path.string());
    if(role==Qt::DecorationRole && index.column()==0 && !n->diagnostic.empty()) return QApplication::style()->standardIcon(QStyle::SP_MessageBoxWarning);
    if(role==Qt::ToolTipRole) {
        std::string text=n->diagnostic;
        if(!n->fetched && !n->blocked) text += (text.empty() ? "" : "\n") + std::string("Dependencies have not been analyzed. Expand to inspect.");
        if(text.empty()) text="Dependency analysis complete.";
        return q(text);
    }
    return {};
}
bool DependenciesModel::hasChildren(const QModelIndex& parent) const {
    if(parent.isValid() && parent.column()!=0) return false;
    const auto* n=node(parent);
    return !n->children.empty() || (!n->fetched && !n->blocked);
}
bool DependenciesModel::canFetchMore(const QModelIndex& parent) const {
    if(parent.isValid() && parent.column()!=0) return false;
    auto* n=node(parent); return !n->fetched && !n->blocked;
}
void DependenciesModel::fetchMore(const QModelIndex& index) { if(canFetchMore(index)) populate(node(index),index); }
void DependenciesModel::populate(Node* n,const QModelIndex& index) {
    n->fetched=true;
    if(!n->analysis) n->analysis=analysis_.inspect(n->path);
    for(const auto& d:n->analysis->diagnostics) n->diagnostic += (n->diagnostic.empty() ? "" : "\n") + d.message;
    if(!n->diagnostic.empty() && reportWarning) reportWarning(q(n->name+": "+n->diagnostic));
    auto dependencies=n->analysis->dependencies;
    std::stable_sort(dependencies.begin(),dependencies.end(),[](const auto& a,const auto& b){return a.name<b.name;});
    const auto count=std::min<std::size_t>(dependencies.size(),1000-total_);
    auto context=resolver_.childrenContext(*n->analysis,n->context);
    std::vector<std::unique_ptr<Node>> added;
    for(std::size_t i=0;i<count;++i) {
        const auto& dep=dependencies[i];
        auto child=std::make_unique<Node>(); child->parent=n; child->name=dep.name; child->depth=n->depth+1; child->context=context;
        auto resolved=resolver_.resolve(dep,*n->analysis,n->context);
        child->path=resolved.path; child->diagnostic=resolved.diagnostic;
        child->blocked=resolved.status!=ResolutionStatus::Found;
        if(!child->blocked) {
            child->canonical=canonicalKey(child->path);
            for(auto* ancestor=n;ancestor;ancestor=ancestor->parent) if(ancestor->canonical==child->canonical) {
                child->blocked=true; child->diagnostic="Dependency cycle: canonical path is already in the ancestor chain."; break;
            }
            if(child->depth>=10) { child->blocked=true; child->diagnostic += "\nMaximum depth (10) reached; dependencies have not been analyzed."; }
        }
        if(!child->diagnostic.empty() && reportWarning) reportWarning(q(child->name+": "+child->diagnostic));
        added.push_back(std::move(child));
    }
    if(count) {
        beginInsertRows(index,0,static_cast<int>(count)-1);
        n->children=std::move(added); total_+=count;
        endInsertRows();
    }
    if(count<dependencies.size()) {
        n->diagnostic += "\nTree limit (1,000 nodes) reached; "+std::to_string(dependencies.size()-count)+" dependencies omitted.";
        if(reportWarning) reportWarning(q(n->diagnostic));
    }
    if(index.isValid()) emit dataChanged(index,index.siblingAtColumn(1),{Qt::ToolTipRole,Qt::DecorationRole});
    if(!count && index.isValid()) { // Refresh the expansion indicator after discovering an empty list.
        emit layoutChanged();
    }
}
}
