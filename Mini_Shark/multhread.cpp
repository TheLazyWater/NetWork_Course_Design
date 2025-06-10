#include "multhread.h"
#include <QDebug>


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
            qDebug()<<timeString;       //输出时间信息
        }
    }
}


