#pragma once
#include "analysis/Symbols.h"
#include <QWidget>
namespace fileinfo {
class SymbolsWidget final : public QWidget {
public:
    explicit SymbolsWidget(QWidget* parent=nullptr);
    void reset(const fs::path& path);
    void populate();
private:
    fs::path path_;
    bool loaded_{};
    class Impl;
    Impl* impl_;
};
}
