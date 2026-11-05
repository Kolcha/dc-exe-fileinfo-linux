#include "ViewerWidget.h"
#include <QApplication>
int main(int argc,char** argv) {
    QApplication app(argc,argv);
    fileinfo::ViewerWidget viewer; viewer.resize(1000,700);
    if(argc>1) viewer.load(argv[1]);
    viewer.show(); return app.exec();
}
