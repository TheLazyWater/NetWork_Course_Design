#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <1.h>
#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QToolBar>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QAction *actionstart_capture;
    QAction *actionclear_all;
    QAction *actionup;
    QAction *actiondown;
    QAction *actionTop;
    QAction *actionEnd;
    QWidget *centralwidget;
    QVBoxLayout *verticalLayout;
    QWidget *widget;
    QHBoxLayout *horizontalLayout;
    QComboBox *comboBox;
    QSpacerItem *horizontalSpacer;
    QLineEdit *lineEdit;
    QSplitter *splitter;
    QTableWidget *tableWidget;
    QTreeWidget *treeWidget;
    TrafficAnalyzer *trafficAnalyzerPlaceholder;
    QMenuBar *menubar;
    QMenu *menu;
    QMenu *menuedit;
    QMenu *menuRun;
    QMenu *menuhelp;
    QStatusBar *statusbar;
    QToolBar *toolBar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
        MainWindow->resize(1425, 751);
        QIcon icon;
        icon.addFile(QString::fromUtf8(":/shark.png"), QSize(), QIcon::Normal, QIcon::Off);
        MainWindow->setWindowIcon(icon);
        actionstart_capture = new QAction(MainWindow);
        actionstart_capture->setObjectName(QString::fromUtf8("actionstart_capture"));
        QIcon icon1;
        icon1.addFile(QString::fromUtf8(":/start.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionstart_capture->setIcon(icon1);
        actionclear_all = new QAction(MainWindow);
        actionclear_all->setObjectName(QString::fromUtf8("actionclear_all"));
        QIcon icon2;
        icon2.addFile(QString::fromUtf8(":/empty.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionclear_all->setIcon(icon2);
        actionup = new QAction(MainWindow);
        actionup->setObjectName(QString::fromUtf8("actionup"));
        QIcon icon3;
        icon3.addFile(QString::fromUtf8(":/up.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionup->setIcon(icon3);
        actiondown = new QAction(MainWindow);
        actiondown->setObjectName(QString::fromUtf8("actiondown"));
        QIcon icon4;
        icon4.addFile(QString::fromUtf8(":/down.png"), QSize(), QIcon::Normal, QIcon::Off);
        actiondown->setIcon(icon4);
        actionTop = new QAction(MainWindow);
        actionTop->setObjectName(QString::fromUtf8("actionTop"));
        QIcon icon5;
        icon5.addFile(QString::fromUtf8(":/upest.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionTop->setIcon(icon5);
        actionEnd = new QAction(MainWindow);
        actionEnd->setObjectName(QString::fromUtf8("actionEnd"));
        QIcon icon6;
        icon6.addFile(QString::fromUtf8(":/downest.png"), QSize(), QIcon::Normal, QIcon::Off);
        actionEnd->setIcon(icon6);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
        centralwidget->setMouseTracking(false);
        centralwidget->setTabletTracking(false);
        centralwidget->setAcceptDrops(false);
        verticalLayout = new QVBoxLayout(centralwidget);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        widget = new QWidget(centralwidget);
        widget->setObjectName(QString::fromUtf8("widget"));
        horizontalLayout = new QHBoxLayout(widget);
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        comboBox = new QComboBox(widget);
        comboBox->setObjectName(QString::fromUtf8("comboBox"));
        comboBox->setMaximumSize(QSize(600, 16777215));

        horizontalLayout->addWidget(comboBox);

        horizontalSpacer = new QSpacerItem(20, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        lineEdit = new QLineEdit(widget);
        lineEdit->setObjectName(QString::fromUtf8("lineEdit"));
        lineEdit->setMinimumSize(QSize(0, 0));

        horizontalLayout->addWidget(lineEdit);


        verticalLayout->addWidget(widget);

        splitter = new QSplitter(centralwidget);
        splitter->setObjectName(QString::fromUtf8("splitter"));
        splitter->setOrientation(Qt::Vertical);
        tableWidget = new QTableWidget(splitter);
        tableWidget->setObjectName(QString::fromUtf8("tableWidget"));
        tableWidget->setMinimumSize(QSize(0, 200));
        QFont font;
        font.setFamily(QString::fromUtf8("Consolas"));
        font.setPointSize(11);
        tableWidget->setFont(font);
        splitter->addWidget(tableWidget);
        treeWidget = new QTreeWidget(splitter);
        QTreeWidgetItem *__qtreewidgetitem = new QTreeWidgetItem();
        __qtreewidgetitem->setText(0, QString::fromUtf8("1"));
        treeWidget->setHeaderItem(__qtreewidgetitem);
        treeWidget->setObjectName(QString::fromUtf8("treeWidget"));
        treeWidget->setMinimumSize(QSize(0, 200));
        treeWidget->setMaximumSize(QSize(16777215, 1000));
        QFont font1;
        font1.setFamily(QString::fromUtf8("Consolas"));
        font1.setPointSize(12);
        font1.setBold(false);
        font1.setWeight(50);
        treeWidget->setFont(font1);
        splitter->addWidget(treeWidget);
        trafficAnalyzerPlaceholder = new TrafficAnalyzer(splitter);
        trafficAnalyzerPlaceholder->setObjectName(QString::fromUtf8("trafficAnalyzerPlaceholder"));
        splitter->addWidget(trafficAnalyzerPlaceholder);

        verticalLayout->addWidget(splitter);

        MainWindow->setCentralWidget(centralwidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName(QString::fromUtf8("menubar"));
        menubar->setGeometry(QRect(0, 0, 1425, 25));
        menu = new QMenu(menubar);
        menu->setObjectName(QString::fromUtf8("menu"));
        menuedit = new QMenu(menubar);
        menuedit->setObjectName(QString::fromUtf8("menuedit"));
        menuRun = new QMenu(menubar);
        menuRun->setObjectName(QString::fromUtf8("menuRun"));
        menuhelp = new QMenu(menubar);
        menuhelp->setObjectName(QString::fromUtf8("menuhelp"));
        MainWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName(QString::fromUtf8("statusbar"));
        MainWindow->setStatusBar(statusbar);
        toolBar = new QToolBar(MainWindow);
        toolBar->setObjectName(QString::fromUtf8("toolBar"));
        MainWindow->addToolBar(Qt::TopToolBarArea, toolBar);

        menubar->addAction(menu->menuAction());
        menubar->addAction(menuedit->menuAction());
        menubar->addAction(menuRun->menuAction());
        menubar->addAction(menuhelp->menuAction());
        menuedit->addAction(actionup);
        menuedit->addAction(actiondown);
        menuedit->addAction(actionTop);
        menuedit->addAction(actionEnd);
        menuRun->addAction(actionstart_capture);
        menuRun->addAction(actionclear_all);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        actionstart_capture->setText(QCoreApplication::translate("MainWindow", "start/stop", nullptr));
        actionclear_all->setText(QCoreApplication::translate("MainWindow", "clear all", nullptr));
        actionup->setText(QCoreApplication::translate("MainWindow", "up", nullptr));
        actiondown->setText(QCoreApplication::translate("MainWindow", "down", nullptr));
        actionTop->setText(QCoreApplication::translate("MainWindow", "Top", nullptr));
        actionEnd->setText(QCoreApplication::translate("MainWindow", "End", nullptr));
        menu->setTitle(QCoreApplication::translate("MainWindow", "project", nullptr));
        menuedit->setTitle(QCoreApplication::translate("MainWindow", "edit", nullptr));
        menuRun->setTitle(QCoreApplication::translate("MainWindow", "Run", nullptr));
        menuhelp->setTitle(QCoreApplication::translate("MainWindow", "help", nullptr));
        toolBar->setWindowTitle(QCoreApplication::translate("MainWindow", "toolBar", nullptr));
        (void)MainWindow;
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
