#include "wlxplugin.h"
#include "ui/ViewerWidget.h"
#include <QApplication>
#include <cstdio>
#include <memory>
#define WLX_EXPORT extern "C" __attribute__((visibility("default")))
WLX_EXPORT HWND DCPCALL ListLoad(HWND parent,char* filename,int) {
    try {
        if(!filename || !qobject_cast<QApplication*>(QCoreApplication::instance()) || !fileinfo::isElf(filename)) return nullptr;
        auto view=std::make_unique<fileinfo::ViewerWidget>(reinterpret_cast<QWidget*>(parent));
        view->load(filename); view->show(); return view.release();
    } catch(...) { return nullptr; }
}
WLX_EXPORT int DCPCALL ListLoadNext(HWND,HWND window,char* filename,int) {
    if(!window || !filename) return LISTPLUGIN_ERROR;
    try { return reinterpret_cast<fileinfo::ViewerWidget*>(window)->load(filename) ? LISTPLUGIN_OK : LISTPLUGIN_ERROR; }
    catch(...) { // Clear old contents even when analysis could not allocate its result.
        try { reinterpret_cast<fileinfo::ViewerWidget*>(window)->load({}); } catch(...) {}
        return LISTPLUGIN_ERROR;
    }
}
WLX_EXPORT void DCPCALL ListCloseWindow(HWND window) { delete reinterpret_cast<fileinfo::ViewerWidget*>(window); }
WLX_EXPORT void DCPCALL ListGetDetectString(char* buffer,int maxlen) {
    if(buffer && maxlen>0) std::snprintf(buffer,static_cast<std::size_t>(maxlen),"[0]=127 & [1]=69 & [2]=76 & [3]=70");
}
