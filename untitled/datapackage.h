#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H
#include "Format.h"
#include <QString>


class datapackage
{
private:
    u_int data_length; //数据包长度
    QString timeStamp;  //时间戳
    QString info;
    int package_type;  //数据包类型
protected:
    static QString byteToString(u_char*str,int size); //一字节数据转16进制
public:
    const u_char*pkt_content;  //信息初始指针

protected:
    /*
     * turn the byteArray to QString
    */
    static QString byteToHex(u_char*str,int size);

public:
    datapackage();
    //成员变量操作函数  存、取
    void setDataLength(u_int data_length);
    void setTimeStamp(QString timeStamp);
    void setPackageType(int type);
    void setPointer(const u_char*pkt_content,int size);
    void setInfo(QString info);

    QString getDataLength();
    QString getTimeStamp();
    QString getPackageType();
    QString getInfo();
    QString getSourse();
    QString getDestination();

    QString getDesMacAddr();
    QString getSrcMacAddr();
    QString getMacType();

    QString getDesIpAddr();                   // get the destination ip address
    QString getSrcIpAddr();                   // get the source ip address
    QString getIpVersion();                   // get the ip version
    QString getIpHeaderLength();              // get the ip head length
    QString getIpTos();                       // get the ip tos
    QString getIpTotalLength();               // get the ip total package length
    QString getIpIdentification();            // get the ip identification
    QString getIpFlag();                      // get the ip flag
    QString getIpReservedBit();               // the reserved bit
    QString getIpDF();                        // Don't fragment
    QString getIpMF();                        // More fragment
    QString getIpFragmentOffset();            // get the offset of package
    QString getIpTTL();                       // get ip ttl [time to live]
    QString getIpProtocol();                  // get the ip protocol
    QString getIpCheckSum();                  // get the checksum

    // get the arp info
    QString getArpHardwareType();             // get arp hardware type
    QString getArpProtocolType();             // get arp protocol type
    QString getArpHardwareLength();           // get arp hardware length
    QString getArpProtocolLength();           // get arp protocol length
    QString getArpOperationCode();            // get arp operation code
    QString getArpSourceEtherAddr();          // get arp source ethernet address
    QString getArpSourceIpAddr();             // get arp souce ip address
    QString getArpDestinationEtherAddr();     // get arp destination ethernet address
    QString getArpDestinationIpAddr();        // get arp destination ip address

    // get the tcp info
    QString getTcpSourcePort();               // get tcp source port
    QString getTcpDestinationPort();          // get tcp destination port
    QString getTcpSequence();                 // get tcp sequence
    QString getTcpAcknowledgment();           // get acknowlegment
    QString getTcpHeaderLength();             // get tcp head length
    QString getTcpRawHeaderLength();          // get tcp raw head length [default is 0x05]
    QString getTcpFlags();                    // get tcp flags
    QString getTcpPSH();                      // PSH flag
    QString getTcpACK();                      // ACK flag
    QString getTcpSYN();                      // SYN flag
    QString getTcpURG();                      // URG flag
    QString getTcpFIN();                      // FIN flag
    QString getTcpRST();                      // RST flag
    QString getTcpWindowSize();               // get tcp window size
    QString getTcpCheckSum();                 // get tcp checksum
    QString getTcpUrgentPointer();            // get tcp urgent pointer
    QString getTcpOperationKind(int kind);    // get tcp option kind
    int getTcpOperationRawKind(int offset);   // get tcp raw option kind
};

#endif // DATAPACKAGE_H
