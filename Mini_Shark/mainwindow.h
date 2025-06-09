#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap.h"

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

private:
    Ui::MainWindow *ui;
    pcap_if_t *all_devices;                 // all adapter device
    pcap_if_t *device;                      // An adapter
    pcap_t *pointer;                        // data package pointer
    char errbuf[PCAP_ERRBUF_SIZE];          // error buffer
};
#endif // MAINWINDOW_H
