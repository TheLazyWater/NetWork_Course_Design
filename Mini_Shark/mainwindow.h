#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "capture.h"
#include "pcap.h"
#include "winsock2.h"
#include <QVector>

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
    void on_tableWidget_cellClicked(int row, int column);
    void on_lineEdit_returnPressed();
    void on_lineEdit_textChanged(const QString &arg1);
    void on_tableWidget_currentCellChanged(int currentRow, int currentColumn, int previousRow, int previousColumn);

public slots:
    void handleMessage(DataPackage data);

private:
    Ui::MainWindow *ui;
    pcap_if_t *all_devices;                 // all adapter device数据结构类似没有头节点的链表
    pcap_if_t *device;                      // An adapter指向当前设备
    pcap_t *pointer;                        // data package pointer设备描述符
    QVector<DataPackage>pData;              //数据包容器（变长数组）
    int countNumber;                        //数据包个数
//    int numberRow;
    int rowNumber;                          // 选中的数据包的行号，即当前行
    QVector<DataPackage>data;               // store data
    bool isStart;                           // the thread is start or not线程标志
    char errbuf[PCAP_ERRBUF_SIZE];          // error buffer报错缓冲区
};
#endif // MAINWINDOW_H
