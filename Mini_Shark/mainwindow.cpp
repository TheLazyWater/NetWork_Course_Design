#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    showNetworkCard();
    static bool index = false;
    connect(ui->actionrunandstop,&QAction::triggered,this,[=]()
    {
        index = !index;
        if (index)
        {
            //开始
            capture();
        }
        else
        {
            //
        }
    });
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::showNetworkCard()
{
    int n = pcap_findalldevs(&all_devices,errbuf);
    ui->comboBox->clear();
    if(n == -1){
        statusBar()->showMessage("There is something wrong" + QString(errbuf));
        ui->comboBox->addItem("Cannot find a matching network card, please restart and test");
        return;
    }
    ui->comboBox->clear();
    ui->comboBox->addItem("please chose the Network Card!");
    for(device = all_devices;device!= nullptr;device = device->next){
        QString device_name = device->name;
        device_name.replace("\\Device\\","");
        QString device_description = device->description;
        QString item = device_name + "   " + device_description;
        ui->comboBox->addItem(item);
    }
}


void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    int i = 0;
    if (index != 0)
    {
        for (device = all_devices; i < index -1 ; i++,device = device->next);
    }
    return;
}


int MainWindow::capture()
{
    if (device)
    {
        pointer = pcap_open_live(device->name,65536,1,1000,errbuf);
    }
    else
        return -1;
    if (!pointer)
    {
        pcap_freealldevs(all_devices);
        device = nullptr;
        return -1;
    }
    else
    {
        if (pcap_datalink(pointer) != DLT_EN10MB)
        {
            pcap_close(pointer);
            pcap_freealldevs(all_devices);
            device = nullptr;
            pointer = nullptr;
            return -1;
        }
        statusBar()->showMessage(device->name);
    }
    return 0;
}
