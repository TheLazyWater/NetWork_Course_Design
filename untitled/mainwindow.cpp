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
                numberROW = -1;

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
    ui->treeWidget->setHeaderHidden(true);//隐藏头部
}

MainWindow::~MainWindow()
{
    int dataSize = pData.size();
    for (int i = 0;i < dataSize; i++) {
        free((char*)(this->pData[i].pkt_content));
        this->pData[i].pkt_content = nullptr;

    }
    QVector<datapackage>().swap(pData);
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



void MainWindow::on_tableWidget_cellClicked(int row, int column) //row选中行
{
    if(row ==  numberROW || row < 0){//选中响应一次
        return;
    }else{
        ui->treeWidget->clear();
        numberROW = row;
        if(numberROW<0 || numberROW > countNumber)
            return;
        QString desMac = pData[numberROW].getDestination();
        QString srcMac = pData[numberROW].getSrcMacAddr();
        QString type = pData[numberROW].getMacType();
        QString tree = "Ethernet,Src:" + srcMac + "Dst:" + desMac;
        QTreeWidgetItem*item = new QTreeWidgetItem(QStringList()<<tree);  //树形结构,QStringList匿名对象
        ui->treeWidget->addTopLevelItem(item);
        item->addChild(new QTreeWidgetItem(QStringList()<<"Destination" + desMac));//嵌套
        item->addChild(new QTreeWidgetItem(QStringList()<<"Source" + srcMac));
        item->addChild(new QTreeWidgetItem(QStringList()<<"type" + type));

        QString packageType = pData[numberROW].getPackageType();
        if(packageType == "ARP"){
            QString ArpType = pData[numberROW].getArpOperationCode();
            QTreeWidgetItem*item2 = new QTreeWidgetItem(QStringList()<<"Address Resolution Protocol " + ArpType);
            ui->treeWidget->addTopLevelItem(item2);
            QString HardwareType = pData[numberROW].getArpHardwareType();
            QString protocolType = pData[numberROW].getArpProtocolType();
            QString HardwareSize = pData[numberROW].getArpHardwareLength();
            QString protocolSize = pData[numberROW].getArpProtocolLength();
            QString srcMacAddr = pData[numberROW].getArpSourceEtherAddr();
            QString desMacAddr = pData[numberROW].getArpDestinationEtherAddr();
            QString srcIpAddr = pData[numberROW].getArpSourceIpAddr();
            QString desIpAddr = pData[numberROW].getArpDestinationIpAddr();

            item2->addChild(new QTreeWidgetItem(QStringList()<<"Hardware type:" + HardwareType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Protocol type:" + protocolType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Hardware size:" + HardwareSize));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Protocol size:" + protocolSize));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Opcode:" + ArpType));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Sender MAC address:" + srcMacAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Sender IP address:" + srcIpAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Target MAC address:" + desMacAddr));
            item2->addChild(new QTreeWidgetItem(QStringList()<<"Target IP address:" + desIpAddr));
            return;
        }else{
            QString srcIp = pData[numberROW].getSrcIpAddr();
                        QString desIp = pData[numberROW].getDesIpAddr();

                        QTreeWidgetItem*item3 = new QTreeWidgetItem(QStringList()<<"Internet Protocol Version 4, Src:" + srcIp + ", Dst:" + desIp);
                        ui->treeWidget->addTopLevelItem(item3);

                        QString version = pData[numberROW].getIpVersion();
                        QString headerLength = pData[numberROW].getIpHeaderLength();
                        QString Tos = pData[numberROW].getIpTos();
                        QString totalLength = pData[numberROW].getIpTotalLength();
                        QString id = "0x" + pData[numberROW].getIpIdentification();
                        QString flags = pData[numberROW].getIpFlag();
                        if(flags.size()<2)
                            flags = "0" + flags;
                        flags = "0x" + flags;
                        QString FragmentOffset = pData[numberROW].getIpFragmentOffset();
                        QString ttl = pData[numberROW].getIpTTL();
                        QString protocol = pData[numberROW].getIpProtocol();
                        QString checksum = "0x" + pData[numberROW].getIpCheckSum();
                        int dataLengthofIp = totalLength.toUtf8().toInt() - 20;
                        item3->addChild(new QTreeWidgetItem(QStringList()<<"0100 .... = Version:" + version));
                        item3->addChild(new QTreeWidgetItem(QStringList()<<".... 0101 = Header Length:" + headerLength));
                        item3->addChild(new QTreeWidgetItem(QStringList()<<"TOS:" + Tos));
                        item3->addChild(new QTreeWidgetItem(QStringList()<<"Total Length:" + totalLength));
                        item3->addChild(new QTreeWidgetItem(QStringList()<<"Identification:" + id));

                        QString reservedBit = pData[numberROW].getIpReservedBit();
                        QString DF = pData[numberROW].getIpDF();
                        QString MF = pData[numberROW].getIpMF();
                        QString FLAG = ",";

                        if(reservedBit == "1"){
                            FLAG += "Reserved bit";
                        }
                        else if(DF == "1"){
                            FLAG += "Don't fragment";
                        }
                        else if(MF == "1"){
                            FLAG += "More fragment";
                        }
                        if(FLAG.size() == 1)
                            FLAG = "";
                        QTreeWidgetItem*bitTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flags + FLAG);
                        item3->addChild(bitTree);
                        QString temp = reservedBit == "1"?"Set":"Not set";
                        bitTree->addChild(new QTreeWidgetItem(QStringList()<<reservedBit + "... .... = Reserved bit:" + temp));
                        temp = DF == "1"?"Set":"Not set";
                        bitTree->addChild(new QTreeWidgetItem(QStringList()<<"." + DF + ".. .... = Don't fragment:" + temp));
                        temp = MF == "1"?"Set":"Not set";
                        bitTree->addChild(new QTreeWidgetItem(QStringList()<<".." + MF + ". .... = More fragment:" + temp));

                        item3->addChild(new QTreeWidgetItem(QStringList()<<"Fragment Offset:" + FragmentOffset));
                        item3->addChild(new QTreeWidgetItem(QStringList()<<"Time to Live:" + ttl));
                        item3->addChild(new QTreeWidgetItem(QStringList()<<"Protocol:" + protocol));
                        item3->addChild(new QTreeWidgetItem(QStringList()<<"Header checksum:" + checksum));
                        item3->addChild(new QTreeWidgetItem(QStringList()<<"Source Address:" + srcIp));
                        item3->addChild(new QTreeWidgetItem(QStringList()<<"Destination Address:" + desIp));
        }
    }




}












