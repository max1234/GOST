#include <QtGui/QApplication>
#include "dialog.h"

int main(int argc, char *argv[])
{   QApplication a(argc, argv);
    Dialog w;
    w.setWindowTitle("GOST");
    w.show();
    return a.exec();}
