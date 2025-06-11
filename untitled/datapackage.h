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
};

#endif // DATAPACKAGE_H
