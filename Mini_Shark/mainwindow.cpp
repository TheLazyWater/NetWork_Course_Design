#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>
#include <QDebug>
#include "multhread.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    statusBar()->showMessage("welcome to Mini Shark!");
    // set the toolbar
//    ui->toolBar->addAction(ui->actionstart_capture);
//    ui->toolBar->addAction(ui->actionclear_all);
//    ui->toolBar->addAction(ui->actionup);
//    ui->toolBar->addAction(ui->actiondown);
//    ui->toolBar->addAction(ui->actionTop);
//    ui->toolBar->addAction(ui->actionEnd);
    ui->toolBar->addAction(ui->actionrunandstop);
    ui->toolBar->addAction(ui->actionclear);
    countNumber = 0;
    showNetworkCard();
    static bool index = false;
    multhread* thread = new multhread;          //创建实例化对象
    connect(ui->actionrunandstop,&QAction::triggered,this,[=]()
    {
        index = !index;
        if (index)
        {
            //开始
            ui->tableWidget->clearContents();
            ui->tableWidget->setRowCount(0);
            countNumber = 0;

            /*释放内存*/
            int dataSize = this->pData.size();
            for (int i = 0; i < dataSize; i++)
            {
                free((char*)(this->pData[i].pkt_content));
                this->pData[i].pkt_content = nullptr;
            }
            QVector<DataPackage>().swap(pData);

            int res = capture();
            if (res != -1  &&  pointer)     //设备打开成功
            {
                thread->setPointer(pointer);        //传递设备指针
                thread->setFlag();                  //设置开关位
                thread->start();
                ui->actionrunandstop->setIcon(QIcon(":/stop.png"));
                ui->comboBox->setEnabled(false);
            }
            else                //设备打开失败
            {
                index = !index;
                countNumber = 0;
            }
        }
        else
        {
            thread->resetFlag();
            thread->quit();     //放弃争夺cpu时间片
            thread->wait();     //等待资源释放
            ui->actionrunandstop->setIcon(QIcon(":/start.png"));
            ui->comboBox->setEnabled(true);
            pcap_close(pointer);
            pointer = nullptr;
        }
    });
    connect(thread,&multhread::send,this,&MainWindow::handleMessage);
    // initialization
    ui->tableWidget->setShowGrid(false);
    ui->toolBar->setMovable(false);            //禁止移动工具栏
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setColumnCount(7);
//    readOnlyDelegate = new ReadOnlyDelegate();
//    ui->tableWidget->setItemDelegate(readOnlyDelegate);
    QStringList title = {"NO.","Time","Source","Destination","Protocol","Length","Info"};
    ui->tableWidget->setHorizontalHeaderLabels(title);
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);       //设置表格每一行的文字像素大小为30
    ui->tableWidget->setColumnWidth(0,50);
    ui->tableWidget->setColumnWidth(1,150);
    ui->tableWidget->setColumnWidth(2,300);
    ui->tableWidget->setColumnWidth(3,300);
    ui->tableWidget->setColumnWidth(4,100);
    ui->tableWidget->setColumnWidth(5,100);
    ui->tableWidget->setColumnWidth(6,1000);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->treeWidget->setHeaderHidden(true);
    ui->tableWidget->setShowGrid(false);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
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


void MainWindow::handleMessage(DataPackage data)
{
    ui->tableWidget->insertRow(countNumber);
    this->pData.push_back(data);
    QString type = data.getPackageType();
    QColor color;
    // show different color
    if(type == TCP){
        color = QColor(216,191,216);
    }else if(type == TCP){
        color = QColor(144,238,144);
    }
    else if(type == ARP){
        color = QColor(238,238,0);
    }
    else if(type == DNS){
        color = QColor(255,255,224);
    }else if(type == TLS || type == SSL){
        color = QColor(210,149,210);
    }else{
        color = QColor(255,218,185);
    }
    ui->tableWidget->setItem(countNumber,0,new QTableWidgetItem(QString::number(countNumber + 1)));
    ui->tableWidget->setItem(countNumber,1,new QTableWidgetItem(data.getTimeStamp()));
    ui->tableWidget->setItem(countNumber,2,new QTableWidgetItem(data.getSource()));
    ui->tableWidget->setItem(countNumber,3,new QTableWidgetItem(data.getDestination()));
    ui->tableWidget->setItem(countNumber,4,new QTableWidgetItem(type));
    ui->tableWidget->setItem(countNumber,5,new QTableWidgetItem(data.getDataLength()));
    ui->tableWidget->setItem(countNumber,6,new QTableWidgetItem(data.getInfo()));
    // set color
    for(int i = 0;i < 7;i++){
        ui->tableWidget->item(countNumber,i)->setBackground(color);
    }
    countNumber++;
}
