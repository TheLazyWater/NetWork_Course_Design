#ifndef MULTHREAD_H
#define MULTHREAD_H
#include <QThread>
#include "pcap.h"
#include "datapackage.h"

class multhread:public QThread
{
    Q_OBJECT
public:
    multhread();
    bool setPointer(pcap_t*pointer);
    void setFlag();
    void resetFlag();
    void run() override;
    int ethernetPackageHandle(const u_char*pkt_content,QString&info);
    int ipPackageHandle(const u_char*pkt_content,int&ipPackge); //ipPackage数据承载量
    int tcpPackageHandle(const u_char*pkt_content,QString&info,int ipPackge);
    int udpPackageHandle(const u_char*pkt_content,QString&info);
    QString arpPackageHandle(const u_char*pkt_content);

protected:
    static QString byteToString(u_char*str,int size);

    //线程信号发送函数
signals:
    void send(datapackage data);
private:
    pcap_t*pointer;
    struct pcap_pkthdr*header;
    const u_char*pkt_data;
    time_t local_time_sec;
    struct tm local_time;
    char timeString[16];
    bool isDone;
};

#endif // MULTHREAD_H
