#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "datapackage.h"
#include "pcap.h"
#include "winsock2.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void showNetworkCard();
    int capture();

private slots:
    void on_comboBox_currentIndexChanged(int index);
public slots:
    void handleMessage(DataPackage data);

private:
    Ui::MainWindow *ui;
    pcap_if_t *all_devices;                 // all adapter device数据结构类似没有头节点的链表
    pcap_if_t *device;                      // An adapter指向当前设备
    pcap_t *pointer;                        // data package pointer设备描述符
    char errbuf[PCAP_ERRBUF_SIZE];          // error buffer报错缓冲区
};
#endif // MAINWINDOW_H
