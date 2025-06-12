#include "datapackage.h"
#include <QMetaType>
#include "winsock2.h"
#include <QVector>

datapackage::datapackage()
{
    qRegisterMetaType<datapackage>("datapackage");//自定义函数注册
    //初始化
    this->timeStamp = "";
    this->data_length = 0;
    this->package_type = 0;
}

//功能实现
void datapackage::setInfo(QString info){
    this->info = info;
}
void datapackage::setPointer(const u_char *pkt_content,int size){
//    this->pkt_content = pkt_content; //并非直接赋值,内存非法访问
    this->pkt_content = (u_char*)malloc(size);//申请内存
    //存储
    memcpy((char*)(this->pkt_content),pkt_content,size);
}

void datapackage::setTimeStamp(QString timeStamp){
    this->timeStamp = timeStamp;
}

void datapackage::setDataLength(u_int data_length){
    this->data_length =  data_length;
}

QString datapackage::getInfo(){
    return this->info;
}

QString datapackage::getTimeStamp(){
    return this->timeStamp;
}

QString datapackage::getDataLength(){
    return QString::number(this->data_length);
}

QString datapackage::getPackageType(){
    switch(this->package_type){
    case 1:return "ARP";
    case 2:return "ICMP";
    case 3:return "TCP";
    case 4:return "UDP";
    case 5:return "DNS";
    case 6:return "TLS";
    case 7:return "SSL";
    default:return "";
    }
}

QString datapackage::byteToString(u_char *str, int size){
    QString res = "";
    for(int i =0;i<size;i++)
    {
        char one = str[i] >>4;
        if(one>= 0x0A)
            one +=0x41 - 0x0A;
        else one += 0x30; //48
        char two = str[i] &0xF;
        if(one >= 0x0A)
            two += 0x41 - 0x0A;
        else
            two += 0x30;
        res.append(one);
        res.append(two);
    }
    return res;
}

QString datapackage::byteToHex(u_char *str, int size){
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

void datapackage::setPackageType(int type){
    this->package_type = type;
}
QString datapackage::getSourse(){
    if(this->package_type == 1){
        return this->getSrcMacAddr();
    }
    else
        return this->getSrcIpAddr();
}

QString datapackage::getDestination(){
    if(this->package_type == 1){
        return this->getDesMacAddr();
    }
    else
        return this->getDesIpAddr();
}

QString datapackage::getDesMacAddr(){
    ETHER_HEADER*eth;
    eth = (ETHER_HEADER*)(pkt_content);
    u_char*addr = eth->ethernet_des_host;
    if(addr){
        QString res = byteToString(addr,1) + ":"
                + byteToString((addr+1),1) + ":"
                + byteToString((addr+2),1) + ":"
                + byteToString((addr+3),1) + ":"
                + byteToString((addr+4),1) + ":"
                + byteToString((addr+5),1) + ":"
                + byteToString((addr+6),1);
        if(res == "FF:FF:FF:FF:FF:FF"){
            return "FF:FF:FF:FF:FF:FF(Broadcast)";
        }else return res;
    }
}

QString datapackage::getSrcMacAddr(){
    ETHER_HEADER*eth;
    eth = (ETHER_HEADER*)(pkt_content);
    u_char*addr = eth->ethernet_src_host;
    if(addr){
        QString res = byteToString(addr,1) + ":"
                + byteToString((addr+1),1) + ":"
                + byteToString((addr+2),1) + ":"
                + byteToString((addr+3),1) + ":"
                + byteToString((addr+4),1) + ":"
                + byteToString((addr+5),1) + ":"
                + byteToString((addr+6),1);
        if(res == "FF:FF:FF:FF:FF:FF"){
            return "FF:FF:FF:FF:FF:FF(Broadcast)";
        }else return res;
    }
}

QString datapackage::getMacType(){
    ETHER_HEADER*eth;
    eth = (ETHER_HEADER*)(pkt_content);
    u_short type = ntohs(eth->type);
    if(type == 0x800) return "IPv4(0x0800)";
    else if(type == 0x0806) return "ARP(0x0806)";
    else return "";
}

QString datapackage::getDesIpAddr(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    sockaddr_in desAddr;
    desAddr.sin_addr.s_addr = ip->des_addr;
    return QString(inet_ntoa(desAddr.sin_addr));
}

QString datapackage::getSrcIpAddr(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    sockaddr_in srcAddr;
    srcAddr.sin_addr.s_addr = ip->src_addr;
    return QString(inet_ntoa(srcAddr.sin_addr));
}

QString datapackage::getIpVersion(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ip->version_length >> 4);
}

/********************** get ip header length **********************/
QString datapackage::getIpHeaderLength(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    QString res = "";
    int length = ip->version_length & 0x0F;
    if(length == 5) res = "20 bytes (5)";
    else res = QString::number(length*5) + "bytes (" + QString::number(length) + ")";
    return res;
}

/********************** get ip TOS **********************/
QString datapackage::getIpTos(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->TOS));
}
/********************** get ip total length **********************/
QString datapackage::getIpTotalLength(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->total_length));
}
/********************** get ip indentification **********************/
QString datapackage::getIpIdentification(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->identification),16);
}
/********************** get ip flag **********************/
QString datapackage::getIpFlag(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->offset)& 0xe000) >> 8,16);
}
/********************** get ip reverse bit **********************/
QString datapackage::getIpReservedBit(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int bit = (ntohs(ip->offset) & 0x8000) >> 15;
    return QString::number(bit);
}
/********************** get ip DF flag[Don't Fragment] **********************/
QString datapackage::getIpDF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->offset) & 0x4000) >> 14);
}
/********************** get ip MF flag[More Fragment] **********************/
QString datapackage::getIpMF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->offset) & 0x2000) >> 13);
}
/********************** get ip Fragment Offset **********************/
QString datapackage::getIpFragmentOffset(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->offset) & 0x1FFF);
}
/********************** get ip TTL **********************/
QString datapackage::getIpTTL(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ip->ttl);
}
/********************** get ip protocol **********************/
QString datapackage::getIpProtocol(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int protocol = ip->protocol;
    switch (protocol) {
    case 1:return "ICMP (1)";
    case 6:return "TCP (6)";
    case 17:return "UDP (17)";
    default:{
        return "";
    }
    }
}
/********************** get ip checksum **********************/
QString datapackage::getIpCheckSum(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->checksum),16);
}

/* arp info */
QString datapackage::getArpHardwareType(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int type = ntohs(arp->type);
    QString res = "";
    if(type == 0x0001) res = "Ethernet(1)";
    else res = QString::number(type);
    return res;
}
/********************** get arp protocol type **********************/
QString datapackage::getArpProtocolType(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int type = ntohs(arp->protocol);
    QString res = "";
    if(type == 0x0800) res = "IPv4(0x0800)";
    else res = QString::number(type);
    return res;
}
/********************** get hardware length **********************/
QString datapackage::getArpHardwareLength(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    return QString::number(arp->mac_length);
}
/********************** get arp protocol length **********************/
QString datapackage::getArpProtocolLength(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    return QString::number(arp->ip_length);
}
/********************** get arp operator code **********************/
QString datapackage::getArpOperationCode(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int code = ntohs(arp->op_code);
    QString res = "";
    if(code == 1) res  = "request(1)";
    else if(code == 2) res = "reply(2)";
    return res;
}
/********************** get arp source ethernet address **********************/
QString datapackage::getArpSourceEtherAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    u_char*addr;
    if(arp){
        addr = arp->src_eth_addr;
        if(addr){
            QString res = byteToHex(addr,1) + ":"
                    + byteToHex((addr+1),1) + ":"
                    + byteToHex((addr+2),1) + ":"
                    + byteToHex((addr+3),1) + ":"
                    + byteToHex((addr+4),1) + ":"
                    + byteToHex((addr+5),1);
            return res;
        }
    }
    return "";
}
/********************** get arp destination ethernet address **********************/
QString datapackage::getArpDestinationEtherAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    u_char*addr;
    if(arp){
        addr = arp->des_eth_addr;
        if(addr){
            QString res = byteToHex(addr,1) + ":"
                    + byteToHex((addr+1),1) + ":"
                    + byteToHex((addr+2),1) + ":"
                    + byteToHex((addr+3),1) + ":"
                    + byteToHex((addr+4),1) + ":"
                    + byteToHex((addr+5),1);
            return res;
        }
    }
    return "";
}
/********************** get arp source ip address **********************/
QString datapackage::getArpSourceIpAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    if(arp){
        u_char*addr = arp->src_ip_addr;
        QString srcIp = QString::number(*addr) + "."
                + QString::number(*(addr+1)) + "."
                + QString::number(*(addr+2)) + "."
                + QString::number(*(addr+3));
        return srcIp;
    }
    return "";
}
/********************** get arp destination ip address **********************/
QString datapackage::getArpDestinationIpAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    if(arp){
        u_char*addr = arp->des_ip_addr;
        QString desIp = QString::number(*addr) + "."
                + QString::number(*(addr+1)) + "."
                + QString::number(*(addr+2)) + "."
                + QString::number(*(addr+3));
        return desIp;
    }
    return "";
}
