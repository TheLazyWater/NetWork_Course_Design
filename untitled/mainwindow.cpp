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
    statusBar()->showMessage("Welcome to shark!");
    ui->toolBar->addAction(ui->actionrunandstop);
    ui->toolBar->addAction(ui->actionclear);
    countNumber = 0;
    showNetworkCard();
    multhread*thread = new multhread;
    static bool index = false;
    connect(ui->actionrunandstop,&QAction::triggered,this,[=]()
        {
            index = !index;
            if (index)
            {
                //开始
                ui->tableWidget->clearContents();//清空之前捕获
                ui->tableWidget->setRowCount(0);//行数置0
                countNumber = 0;

                int datasize = this->pData.size();
                for (int i=0;i<datasize;i++) {
                    free((char*)(this->pData[i].pkt_content));//释放
                    this->pData[i].pkt_content = nullptr;//指针置空
                }
                //与空容器交换
                QVector<datapackage>().swap(pData);
                int res = capture();
                if(res!= -1 && pointer){
                    thread->setPointer(pointer);
                    thread->setFlag();
                    thread->start();
                    ui->actionrunandstop->setIcon(QIcon(":/stop.png"));
                    ui->comboBox->setEnabled(false);
                }else{
                    index = !index;
                    countNumber = 0;
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

    ui->toolBar->setMovable(false);
    ui->tableWidget->setColumnCount(7);//列数
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    QStringList tital = {"NO.","Time","Source","DEstination","Protocol","Length","Info"};//字段名
    ui->tableWidget->setHorizontalHeaderLabels(tital);

    ui->tableWidget->setColumnWidth(0,50);//默认宽度
    ui->tableWidget->setColumnWidth(1,90);
    ui->tableWidget->setColumnWidth(2,150);
    ui->tableWidget->setColumnWidth(3,150);
    ui->tableWidget->setColumnWidth(4,100);
    ui->tableWidget->setColumnWidth(5,100);
    ui->tableWidget->setColumnWidth(6,1000);

    ui->tableWidget->setShowGrid(false);//网格线
    ui->tableWidget->verticalHeader()->setVisible(false);//垂直标签
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);//选中
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

void MainWindow::HandleMessage(datapackage data){//数据发送主线程
    qDebug()<<data.getTimeStamp()<<" "<<data.getInfo();
    ui->tableWidget->insertRow(countNumber);   //插入新的一行
    this->pData.push_back(data);
    QString type = data.getPackageType(); //类型
    QColor color;
    if(type == "TCP"){
        color = QColor(231,230,255);
    }else if(type == "UDP"){
        color = QColor(144,238,144);
    }else if(type == "ARP"){
        color = QColor(237,225,2);
    }else if(type == "DNS"){
        color = QColor(255,253,224);
    }else{
        color = QColor(255,218,185);
    }

    ui->tableWidget->setItem(countNumber,0,new QTableWidgetItem(QString::number(countNumber)));
    ui->tableWidget->setItem(countNumber,1,new QTableWidgetItem(data.getTimeStamp()));
    ui->tableWidget->setItem(countNumber,2,new QTableWidgetItem(data.getSourse()));
    ui->tableWidget->setItem(countNumber,3,new QTableWidgetItem(data.getDestination()));
    ui->tableWidget->setItem(countNumber,4,new QTableWidgetItem(type));
    ui->tableWidget->setItem(countNumber,5,new QTableWidgetItem(data.getDataLength()));
    ui->tableWidget->setItem(countNumber,6,new QTableWidgetItem(data.getInfo()));
    for(int i=0;i<7;i++){
        ui->tableWidget->item(countNumber,i)->setBackgroundColor(color);
    }
    countNumber++;//数据包个数自增A
}


