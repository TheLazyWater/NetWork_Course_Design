#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "QString"
#include "multhread.h"
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    showNetworkCard();
    multhread*thread = new multhread;
    static bool index = false;
    connect(ui->actionrunandstop,&QAction::triggered,this,[=]()
        {
            index = !index;
            if (index)
            {
                //开始
                int res = capture();
                if(res!= -1 && pointer){
                    thread->setPointer(pointer);
                    thread->setFlag();
                    thread->start();
                    ui->actionrunandstop->setIcon(QIcon(":/stop.png"));
                    ui->comboBox->setEnabled(false);
                }
            }
            else
            {
                thread->resetFlag();
                thread->quit();
                thread->wait();
                ui->actionrunandstop->setIcon(QIcon(":/start.png"));   //更改图标和可编辑状态
                ui->comboBox->setEnabled(true);
                pcap_close(pointer);     //关闭并释放
                pointer = nullptr;

                //
            }
        });
    connect(thread,&multhread::send,this,&MainWindow::HandleMessage);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::showNetworkCard()
{
    int n = pcap_findalldevs(&all_devices,errbuf);
    if(n==-1){
        ui->comboBox->addItem("error:"+QString(errbuf));
    }
    else{
        ui->comboBox->clear();
        ui->comboBox->addItem("please choose card!");
        for(device = all_devices;device!=nullptr;device = device->next){
            QString devicd_name = device->name;
            devicd_name.replace("\\Device\\","");
            QString des = device->description;
            QString item = devicd_name + des;
            ui->comboBox->addItem(item);
        }
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
    if (!device) {
        statusBar()->showMessage("No device selected!");
        return -1;
    }

    pointer = pcap_open_live(device->name, 65536, 1, 1000, errbuf);

    if (!pointer) {
        statusBar()->showMessage("Failed to open device: " + QString(errbuf));
        pcap_freealldevs(all_devices);
        device = nullptr;
        return -1;
    } else {
        if (pcap_datalink(pointer) != DLT_EN10MB) {
            statusBar()->showMessage("This program works only on Ethernet networks.");
            pcap_close(pointer);
            pcap_freealldevs(all_devices);
            device = nullptr;
            pointer = nullptr;
            return -1;
        }
        statusBar()->showMessage("Capturing on: " + QString(device->name));
    }
    return 0;
}

void MainWindow::HandleMessage(datapackage data){
   qDebug()<<data.getTimeStamp()<<" "<<data.getInfo();
}

