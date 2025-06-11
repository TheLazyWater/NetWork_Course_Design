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
    bool setPointer(pcap_t* pointer);      //打开设备描述符的地址
    void setFlag();         //设置开关变量
    void resetFlag();       //重置开关变量
    void run() override;
    int ethernetPackageHandle(const u_char *pkt_content,QString &info);
signals:
    void send(DataPackage data);

private:
    pcap_t* pointer;        //设备标识符指针
    struct pcap_pkthdr* header;         //数据包头部结构指针
    const u_char* pkt_data;     //数据包内容指针
    time_t local_time_sec;      //原始时间变量
    struct tm local_time;       //帮助转换时间变量
    char timeString[16];        //时间戳字符串
    bool isDone;        //开关变量，用来表示线程是否结束
};

#endif // MULTHREAD_H
