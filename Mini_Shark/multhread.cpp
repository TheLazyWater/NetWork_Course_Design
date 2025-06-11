#include "multhread.h"
#include <QDebug>
#include "Format.h"
#include "datapackage.h"

multhread::multhread()
{
    this->isDone = true;
}

bool multhread::setPointer(pcap_t *pointer)
{
    this->pointer = pointer;
    if (pointer)
        return true;
    else
        return false;
}

void multhread::setFlag()
{
    this->isDone = false;
}

void multhread::resetFlag()
{
    this->isDone = true;
}

void multhread::run()
{
    while (true)
    {
        if (isDone)
            break;
        else
        {
            int res = pcap_next_ex(pointer,&header,&pkt_data);      //逐条处理数据包
            if (res == 0)
                continue;
            local_time_sec = header->ts.tv_sec;     //从数据包头部获取原始时间戳
            localtime_s(&local_time,&local_time_sec);             //转换格式
            strftime(timeString,sizeof(timeString),"%H:%M:%S",&local_time);  //转换成字符串
            QString info = "";
            int type = ethernetPackageHandle(pkt_data,info);
            if (type)
            {
                DataPackage data;
                int len = header->len;
                data.setPackageInfo(info);
                data.setDataLength(len);
                data.setTimeStamp(timeString);
                emit send(data);
            }
        }
    }
}

int multhread::ethernetPackageHandle(const u_char *pkt_content, QString &info)
{
    ETHER_HEADER *ethenet;
    u_short content_type;
    ethenet = (ETHER_HEADER*)(pkt_content);
    content_type= ntohs(ethenet->ether_type);
    switch(content_type)
    {
        case 0x0800:        //ip
        {
            int dataPackage = 0;
            int res = ipPackageHandle(pkt_content,dataPackage);
            switch (res) {
            case 1:{// icmp package
//                info = icmpPackageHandle(pkt_content);
                return 2;
            }
            case 6:{// tcp package
                return tcpPackageHandle(pkt_content,info,dataPackage);

            }
            case 17:{ // udp package
                int type = udpPackageHandle(pkt_content,info);
                return type;
            }
            default:break;
            }
            break;
        }
        case 0x0806:       //arp
        {
        info = arpPackageHandle(pkt_content);
        return 1;
        }
        default:
            break;
    }
    return 0;
}

// ip package
int multhread::ipPackageHandle(const u_char *pkt_content,int& ipPackage)
{
    /*
+------+-----+-----+
|   1  |  6  |  17 |
+------+-----+-----+
| ICMP | TCP | UDP |
+------+-----+-----+
*/
    IP_HEADER* ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int protocol = ip->protocol;
    ipPackage = (htons(ip->total_length) - (ip->versiosn_head_length & 0x0F) * 4);
    return protocol;
}

int multhread::tcpPackageHandle(const u_char *pkt_content,QString &info,int ipPackage){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    u_short src = ntohs(tcp->src_port);
    u_short des = ntohs(tcp->des_port);
    QString proSend = "";
    QString proRecv = "";
    int type = 3;
    int delta = (tcp->header_length >> 4) * 4;
    int tcpPayLoad = ipPackage - delta;
    if((src == 443 || des == 443) && (tcpPayLoad > 0)) {
        if(src == 443)
            proSend = "(https)";
        else proRecv = "(https)";
        u_char *ssl;
        ssl = (u_char*)(pkt_content + 14 + 20 + delta);
        u_char isTls = *(ssl);
        ssl++;
        u_short*pointer = (u_short*)(ssl);
        u_short version = ntohs(*pointer);
        if(isTls >= 20 && isTls <= 23 && version >= 0x0301 && version <= 0x0304){
            type = 6;
            switch(isTls){
            case 20:{
                info = "Change Cipher Spec";
                break;
            }
            case 21:{
                info = "Alert";
                break;
            }
            case 22:{
                info = "Handshake";
                ssl += 4;
                u_char type = (*ssl);
                switch (type) {
                case 1: {
                    info += " Client Hello";
                    break;
                }
                case 2: {
                    info += " Server hello";
                    break;
                }
                case 4: {
                    info += " New Session Ticket";
                    break;
                }
                case 11:{
                    info += " Certificate";
                    break;
                }
                case 16:{
                    info += " Client Key Exchange";
                    break;
                }
                case 12:{
                    info += " Server Key Exchange";
                    break;
                }
                case 14:{
                    info += " Server Hello Done";
                    break;
                }
                default:break;
                }
                break;
            }
            case 23:{
                info = "Application Data";
                break;
            }
            default:{
                break;
            }
            }
            return type;
        }else type = 7;
    }

    if(type == 7){
        info = "Continuation Data";
    }
    else{
        info += QString::number(src) + proSend+ "->" + QString::number(des) + proRecv;
        QString flag = "";
        if(tcp->flags & 0x08) flag += "PSH,";
        if(tcp->flags & 0x10) flag += "ACK,";
        if(tcp->flags & 0x02) flag += "SYN,";
        if(tcp->flags & 0x20) flag += "URG,";
        if(tcp->flags & 0x01) flag += "FIN,";
        if(tcp->flags & 0x04) flag += "RST,";
        if(flag != ""){
            flag = flag.left(flag.length()-1);
            info += " [" + flag + "]";
        }
        u_int sequeue = ntohl(tcp->sequence);
        u_int ack = ntohl(tcp->ack);
        u_short window = ntohs(tcp->window_size);
        info += " Seq=" + QString::number(sequeue) + " Ack=" + QString::number(ack) + " win=" + QString::number(window) + " Len=" + QString::number(tcpPayLoad);
    }
    return type;
}

int multhread::udpPackageHandle(const u_char *pkt_content,QString&info)
{
    UDP_HEADER * udp;
    udp = (UDP_HEADER*)(pkt_content + 14 + 20);
    u_short desPort = ntohs(udp->des_port);
    u_short srcPort = ntohs(udp->src_port);
    if(desPort == 53){ // dns query
//        info =  dnsPackageHandle(pkt_content);
        return 5;
    }
    else if(srcPort == 53){// dns reply
//        info =  dnsPackageHandle(pkt_content);
        return 5;
    }
    else{
        QString res = QString::number(srcPort) + "->" + QString::number(desPort);
        res += " len=" + QString::number(ntohs(udp->data_length));
        info = res;
        return 4;
    }
}

QString multhread::arpPackageHandle(const u_char *pkt_content)
{
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    u_short op = ntohs(arp->op_code);
    QString res = "";
    u_char*addr = arp->des_ip_addr;

    QString desIp = QString::number(*addr) + "."
            + QString::number(*(addr+1)) + "."
            + QString::number(*(addr+2)) + "."
            + QString::number(*(addr+3));

    addr = arp->src_ip_addr;
    QString srcIp = QString::number(*addr) + "."
            + QString::number(*(addr+1)) + "."
            + QString::number(*(addr+2)) + "."
            + QString::number(*(addr+3));

    u_char* srcEthTemp = arp->src_eth_addr;
    QString srcEth = byteToHex(srcEthTemp,1) + ":"
            + byteToHex((srcEthTemp+1),1) + ":"
            + byteToHex((srcEthTemp+2),1) + ":"
            + byteToHex((srcEthTemp+3),1) + ":"
            + byteToHex((srcEthTemp+4),1) + ":"
            + byteToHex((srcEthTemp+5),1);

    switch (op){
    case 1:{
        res  = "Who has " + desIp + "? Tell " + srcIp;
        break;
    }
    case 2:{
        res = srcIp + " is at " + srcEth;
        break;
    }
    default:break;
    }
    return res;
}

QString multhread::byteToHex(u_char*str,int size)
{
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
