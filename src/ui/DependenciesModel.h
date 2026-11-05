#pragma once
#include "analysis/DependencyResolver.h"
#include <QAbstractItemModel>
#include <functional>
namespace fileinfo {
class DependenciesModel final : public QAbstractItemModel {
public:
    DependenciesModel(AnalysisContext& analysis, DependencyResolver& resolver, std::shared_ptr<const AnalysisResult> root, QObject* parent=nullptr);
    QModelIndex index(int row,int column,const QModelIndex& parent={}) const override;
    QModelIndex parent(const QModelIndex& index) const override;
    int rowCount(const QModelIndex& parent={}) const override;
    int columnCount(const QModelIndex& ={}) const override { return 2; }
    QVariant data(const QModelIndex& index,int role=Qt::DisplayRole) const override;
    QVariant headerData(int section,Qt::Orientation orientation,int role) const override;
    bool hasChildren(const QModelIndex& parent={}) const override;
    bool canFetchMore(const QModelIndex& parent) const override;
    void fetchMore(const QModelIndex& parent) override;
    std::function<void(const QString&)> reportWarning;
private:
    struct Node {
        Node* parent{};
        std::vector<std::unique_ptr<Node>> children;
        std::string name, diagnostic;
        fs::path path, canonical;
        SearchContext context;
        std::shared_ptr<const AnalysisResult> analysis;
        int depth{};
        bool fetched{}, blocked{};
    };
    Node* node(const QModelIndex& index) const;
    void populate(Node* node,const QModelIndex& index);
    AnalysisContext& analysis_;
    DependencyResolver& resolver_;
    Node root_;
    std::size_t total_{};
};
}
