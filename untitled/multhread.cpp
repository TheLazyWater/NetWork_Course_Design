#include "multhread.h"
#include <QDebug>
#include <Format.h>
#include "datapackage.h"

multhread::multhread()
{
    this->isDone = true;
}

bool multhread::setPointer(pcap_t *pointer){
    this->pointer = pointer;
    if(pointer)
    {
        return true;
    }
    else
    {
        return false;
    }
}

void multhread::setFlag(){
    this->isDone = false;
}

void multhread::resetFlag(){
    this->isDone = true;
}

void multhread::run(){
    while(true)
    {
        if(isDone)
        {
            break;
        }
        else{
            int res = pcap_next_ex(pointer,&header,&pkt_data);
            if(res == 0)
                continue;
            local_time_sec = header->ts.tv_sec;
            localtime_s(&local_time,&local_time_sec);
            strftime(timeString,sizeof (timeString),"%H:%M:%S",&local_time);
//            qDebug()<<timeString;
            QString info = "";
            int type = ethernetPackageHandle(pkt_data,info);
            if(type)
            {
                datapackage data;
                int len = header->len;
                data.setInfo(info);
                data.setDataLength(len);
                data.setTimeStamp(timeString);
                emit send(data);
            }
        }
    }
}

int multhread::ethernetPackageHandle(const u_char *pkt_content, QString &info){
    ETHER_HEADER*ethenet;
    u_short content_type;
    ethenet = (ETHER_HEADER*)(pkt_content);
    content_type = ntohs(ethenet->type);
    switch (content_type) {
    case 0x0800:{
        int ipPackage = 0;
        int res = ipPackageHandle(pkt_content,ipPackage);
        switch (res) {
        case 1:{//icmp
            info = "ICMP";
            return 2;
        }
        case 6:{//tcp
            return tcpPackageHandle(pkt_content,info,ipPackage);
            break;
        }
        case 17:{//udp
            return udpPackageHandle(pkt_content,info);
            break;
        }
        default:break;
        }
        break;
    }
    case 0x0806:{//arp
        info = arpPackageHandle(pkt_content);
        return 1;
    }
    default:break;
    }
    return 0;
}

int multhread::ipPackageHandle(const u_char *pkt_content, int &ipPackge){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);//跳过mac 6+6+2
    int protocol = ip->protocol;//协议
    ipPackge = (ntohs(ip->total_length) - ((ip->version_length)&0x0F) *4);
    return protocol;
}

int multhread::tcpPackageHandle(const u_char *pkt_content, QString &info, int ipPackge){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);//跳过mac和tcp头部
    u_short src = ntohs(tcp->src_port);
    u_short des = ntohs(tcp->des_port);//16位网络字节流转主机字节流

    QString proSend = "";
    QString proRecv = "";

    int type = 3;
    int delta = (tcp->header_length >> 4) *4; //位运算*4得到实际字节数
    int tcpLoader = ipPackge - delta;//tcp数据 = ip数据包 - tcp头部
    //简单判断
    if(src == 443 || des == 443)
    {
        if(src == 443)
        {
            proSend = "(https)";
        }else{
            proRecv = "(https)";
        }
    }
    info += QString::number(src) + proSend + "->" + QString::number(des) + proRecv;//源->目
    //标识符
    QString flag = "";
    if(tcp->flags & 0x08)  flag += "PSH,";
    if(tcp->flags & 0x10)  flag += "ACK,";
    if(tcp->flags & 0x02)  flag += "SYN,";
    if(tcp->flags & 0x20)  flag += "URG,";
    if(tcp->flags & 0x01)  flag += "FIN,";
    if(tcp->flags & 0x04)  flag += "RST,";
    if(flag != ""){
        flag = flag.left(flag.length() - 1);//去掉最后的,
        info += "[" + flag + "]";
    }
    u_int sequence = ntohl(tcp->seqequence);//32位网络转主机
    u_int ack = ntohl(tcp->ack);
    u_short window = ntohs(tcp->window_size);

    info += "Seq" + QString::number(sequence) + "Ack=" + QString::number(ack) +
            "win=" + QString::number(window) + "len=" + QString::number(tcpLoader);
    return type;
}

int multhread::udpPackageHandle(const u_char *pkt_content, QString &info){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 14 + 20);//偏移量
    //源端口，目的端口
    u_short des = ntohs(udp->des_port);
    u_short src = ntohs(udp->src_port);
    if(des == 53 || src == 53)
    {
        return 5;
    }
    else{
        QString res = QString::number(src) + "->" +QString::number(des);
        u_short data_len = ntohs(udp->data_length);
        res += "len =" +QString::number(data_len);
        info = res;
        return 0;
    }
}

QString multhread::arpPackageHandle(const u_char *pkt_content){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);//与ip同层

    u_short op = ntohs(arp->op_code);
    QString res = "";
    u_char*des_addr = arp->des_ip_addr;
    QString desIp = QString::number(*des_addr) + "."
           + QString::number(*(des_addr + 1)) + "."
           + QString::number(*(des_addr + 2)) + "."
           + QString::number(*(des_addr + 3));
    u_char*src_ip = arp->src_ip_addr;
    QString srcIp = QString::number(*src_ip) + "."
           + QString::number(*(src_ip + 1)) + "."
           + QString::number(*(src_ip + 2)) + "."
           + QString::number(*(src_ip + 3));
    u_char*src_eth_addr = arp->src_eth_addr;
    //48位
    QString srcEth = byteToString(src_eth_addr,1) + ":"
            + byteToString((src_eth_addr+1),1) + ":"
            + byteToString((src_eth_addr+1),1) + ":"
            + byteToString((src_eth_addr+1),1) + ":"
            + byteToString((src_eth_addr+1),1) + ":"
            + byteToString((src_eth_addr+1),1) + ":"
            + byteToString((src_eth_addr+1),1);
    if(op == 1){
        res = "who has "+ desIp +"? Tell" + srcIp;//询问
    }
    else if(op == 2)
    {
        res = srcIp + "is at " + srcEth;//应答
    }
    return res;
}

QString multhread::byteToString(u_char *str, int size){
    QString res = "";
    for(int i =0;i<size;i++)
    {
        char one = str[i] >>4;
        if(one>=0x0A)//10
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






