#include "datapackage.h"
#include <QMetaType>
#include "winsock.h"
#include <QVector>

DataPackage::DataPackage()
{
    // register the DataPackage type then
    qRegisterMetaType<DataPackage>("DataPackage");
    this->timeStamp = "";
    this->data_length = 0;
    this->packageType = 0;
    this->pkt_content = nullptr;
}

void DataPackage::setDataLength(unsigned int length){
    this->data_length = length;
}

void DataPackage::setTimeStamp(QString timeStamp){
    this->timeStamp = timeStamp;
}

void DataPackage::setPackageType(int type){
    this->packageType = type;
}

void DataPackage::setPackagePointer(const u_char *pkt_content,int size){
    this->pkt_content = (u_char*)malloc(size);
    if(this->pkt_content != nullptr)
        memcpy((char*)(this->pkt_content),pkt_content,size);
    else this->pkt_content = nullptr;
    //  Do not use  `this->pkt_content = pkt_content;`
}
void DataPackage::setPackageInfo(QString info){
    this->info = info;
}
QString DataPackage::byteToHex(u_char *str, int size){
    QString res = "";
    for(int i = 0;i < size;i++){
        char one = str[i] >> 4;
        if(one >= 0x0A)
            one = one + 0x41 - 0x0A;
        else one = one + 0x30;
        char two = str[i] & 0xF;
        if(two >= 0x0A)
            two = two  + 0x41 - 0x0A;
        else two = two + 0x30;
        res.append(one);
        res.append(two);
    }
    return res;
}

QString DataPackage::getTimeStamp(){
    return this->timeStamp;
}

QString DataPackage::getDataLength(){
    return QString::number(this->data_length);
}

QString DataPackage::getPackageType(){
    switch (this->packageType) {
    case 1:return ARP;
    case 2:return ICMP;
    case 3:return TCP;
    case 4:return UDP;
    case 5:return DNS;
    case 6:return TLS;
    case 7:return SSL;
    // TODU ...more protocol you can add
    default:{
        return "";
    }
    }
}

QString DataPackage::getInfo(){
    return info;
}

//QString DataPackage::getSource(){
//    if(this->packageType == 1)
//        return getArpSourceIpAddr();
//    else return getSrcIpAddr();
//}
//QString DataPackage::getDestination(){
//    if(this->packageType == 1)
//        return getArpDestinationIpAddr();
//    else return getDesIpAddr();
//}
